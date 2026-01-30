const fs = require('fs');
const path = require('path');
const express = require('express');
const zlib = require('zlib');
const crypto = require('crypto');
const { DOMParser } = require('@xmldom/xmldom');
const xpath = require('xpath');
const { SignedXml } = require('xml-crypto');

// Load .env (DEFAULT_IDP_ISSUER) without dotenv dependency
try {
  const envPath = path.join(__dirname, '.env');
  const buf = fs.readFileSync(envPath, 'utf8');
  buf.split('\n').forEach((line) => {
    const m = line.match(/^([^#=]+)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim().replace(/^["']|["']$/g, '');
  });
} catch (e) { /* .env optional */ }

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

const SAML_CONFIG_API_BASE = process.env.SAML_CONFIG_API_BASE || 'https://app.greysolve.com/webhook';

// Fetch SAML config from API by DEFAULT_IDP_ISSUER (used for SSO)
async function getSamlConfig() {
  const issuer = process.env.DEFAULT_IDP_ISSUER;
  if (!issuer) throw new Error('DEFAULT_IDP_ISSUER is required (set in .env or Vercel environment)');
  const url = `${SAML_CONFIG_API_BASE}/saml-config?issuer=${encodeURIComponent(issuer)}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to fetch SAML config: ${res.status}`);
  const data = await res.json();
  const item = Array.isArray(data) ? data[0] : data;
  if (!item) throw new Error('No SAML config found for DEFAULT_IDP_ISSUER');
  return {
    entityId: item.entity_id,
    issuer: item.issuer,
    idpEntryPoint: item.idp_entry_point,
    acsUrl: item.acs_url,
    idpCert: item.idp_cert || ''
  };
}

// =============================================================================
// STEP 1: BUILD THE AUTHNREQUEST XML
// This is what we send to the IdP saying "please authenticate this user"
// =============================================================================
function buildAuthnRequest(config) {
  const id = '_' + crypto.randomBytes(16).toString('hex');
  const issueInstant = new Date().toISOString();
  
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="${id}"
    Version="2.0"
    IssueInstant="${issueInstant}"
    Destination="${config.idpEntryPoint}"
    AssertionConsumerServiceURL="${config.acsUrl}"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
    <saml:Issuer>${config.entityId}</saml:Issuer>
    <samlp:NameIDPolicy
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        AllowCreate="true"/>
</samlp:AuthnRequest>`;

  return { id, xml };
}

// =============================================================================
// STEP 2: ENCODE THE REQUEST FOR REDIRECT
// SAML HTTP-Redirect binding requires: Deflate -> Base64 -> URL encode
// =============================================================================
function encodeAuthnRequest(xml) {
  // Deflate compress (not gzip - raw deflate)
  const deflated = zlib.deflateRawSync(xml);
  
  // Base64 encode
  const base64 = deflated.toString('base64');
  
  // URL encode (special chars need escaping)
  return encodeURIComponent(base64);
}

// =============================================================================
// STEP 3: LOGIN ROUTE - Redirect user to IdP
// =============================================================================
app.get('/login', async (req, res) => {
  try {
    const config = await getSamlConfig();
    const { id, xml } = buildAuthnRequest(config);
    app.locals.pendingRequestId = id;
    console.log('\n=== OUTGOING AUTHNREQUEST ===');
    console.log(xml);
    console.log('=============================\n');
    const encodedRequest = encodeAuthnRequest(xml);
    const redirectUrl = `${config.idpEntryPoint}?SAMLRequest=${encodedRequest}`;
    console.log('Redirecting to IdP:', redirectUrl.substring(0, 100) + '...\n');
    res.redirect(redirectUrl);
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message || 'Failed to start SSO');
  }
});

// =============================================================================
// STEP 4: ASSERTION CONSUMER SERVICE (ACS) - Receive IdP's response
// The IdP POSTs the SAMLResponse here after user authenticates
// =============================================================================
app.post('/saml/acs', async (req, res) => {
  const samlResponse = req.body.SAMLResponse;
  if (!samlResponse) {
    return res.status(400).send('No SAMLResponse received');
  }

  let config;
  try {
    config = await getSamlConfig();
  } catch (err) {
    console.error(err);
    return res.status(500).send(err.message || 'Failed to load SAML config');
  }
  
  console.log('\n=== RECEIVED SAMLRESPONSE (base64) ===');
  console.log(samlResponse.substring(0, 100) + '...');
  
  const xml = Buffer.from(samlResponse, 'base64').toString('utf8');
  console.log('\n=== DECODED SAMLRESPONSE XML ===');
  console.log(xml);
  console.log('================================\n');
  
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const namespaces = {
    samlp: 'urn:oasis:names:tc:SAML:2.0:protocol',
    saml: 'urn:oasis:names:tc:SAML:2.0:assertion',
    ds: 'http://www.w3.org/2000/09/xmldsig#'
  };
  const select = xpath.useNamespaces(namespaces);
  
  const statusCode = select('//samlp:StatusCode/@Value', doc)[0];
  if (!statusCode || !statusCode.value.includes('Success')) {
    return res.status(401).send('SAML authentication failed: ' + (statusCode?.value || 'unknown'));
  }
  
  const signature = select('//ds:Signature', doc)[0];
  if (!signature) {
    return res.status(401).send('No signature found in SAML response');
  }
  
  const sig = new SignedXml();
  sig.keyInfoProvider = { getKey: () => config.idpCert };
  sig.loadSignature(signature);
  const signedXml = signature.parentNode;
  const isValid = sig.checkSignature(signedXml.toString());
  if (!isValid) {
    console.log('Signature validation errors:', sig.validationErrors);
    return res.status(401).send('Invalid SAML signature');
  }
  console.log('✓ Signature validated successfully\n');
  
  const conditions = select('//saml:Conditions', doc)[0];
  if (conditions) {
    const notBefore = conditions.getAttribute('NotBefore');
    const notOnOrAfter = conditions.getAttribute('NotOnOrAfter');
    const now = new Date();
    if (notBefore && new Date(notBefore) > now) {
      return res.status(401).send('SAML assertion not yet valid');
    }
    if (notOnOrAfter && new Date(notOnOrAfter) <= now) {
      return res.status(401).send('SAML assertion expired');
    }
    const audience = select('//saml:AudienceRestriction/saml:Audience/text()', doc)[0];
    if (audience && audience.nodeValue !== config.entityId) {
      return res.status(401).send('SAML assertion not intended for this application');
    }
  }
  
  console.log('✓ Conditions validated\n');
  
  // ---------------------------------------------
  // STEP 4f: Extract the user identity (NameID)
  // This is the "who you are" that replaces username/password
  // ---------------------------------------------
  const nameIdNode = select('//saml:NameID/text()', doc)[0];
  const nameID = nameIdNode ? nameIdNode.nodeValue : null;
  
  if (!nameID) {
    return res.status(401).send('No NameID found in SAML assertion');
  }
  
  console.log('✓ User authenticated:', nameID, '\n');
  
  // ---------------------------------------------
  // STEP 4g: Extract any additional attributes
  // ---------------------------------------------
  const attributes = {};
  const attrNodes = select('//saml:Attribute', doc);
  
  attrNodes.forEach(attr => {
    const name = attr.getAttribute('Name');
    const valueNode = select('saml:AttributeValue/text()', attr)[0];
    if (name && valueNode) {
      attributes[name] = valueNode.nodeValue;
    }
  });
  
  console.log('Attributes:', attributes);
  
  // ---------------------------------------------
  // STEP 5: Create your app's session
  // From here on, YOUR app's authorization takes over
  // ---------------------------------------------
  
  // In production, set a real session cookie here
  // For demo, just show success
  res.send(`
    <h1>SAML Authentication Successful</h1>
    <button onclick="alert('Hello World')">Hello World</button>
    <h2>Identity from IdP:</h2>
    <p><strong>NameID:</strong> ${nameID}</p>
    <h3>Attributes:</h3>
    <pre>${JSON.stringify(attributes, null, 2)}</pre>
    <hr>
    <p>From here, you'd map this identity to a local user and create a session.</p>
  `);
});

// =============================================================================
// METADATA ENDPOINT - IdPs need this to configure trust
// =============================================================================
app.get('/saml/metadata', async (req, res) => {
  try {
    const config = await getSamlConfig();
    const metadata = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="${config.entityId}">
    <md:SPSSODescriptor
        AuthnRequestsSigned="false"
        WantAssertionsSigned="true"
        protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:AssertionConsumerService
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            Location="${config.acsUrl}"
            index="1"/>
    </md:SPSSODescriptor>
</md:EntityDescriptor>`;
    res.type('application/xml');
    res.send(metadata);
  } catch (err) {
    console.error(err);
    res.status(500).send(err.message || 'Failed to load SAML config');
  }
});

// Home page
app.get('/', (req, res) => {
  res.send(`
    <h1>Raw SAML Service Provider</h1>
    <p><a href="/login">Login via SAML</a></p>
    <p><a href="/saml/metadata">View SP Metadata</a></p>
    <p><a href="/index.html">SAML configuration</a></p>
  `);
});

module.exports = app;

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Raw SAML SP running on http://localhost:${PORT}`);
    console.log(`Metadata available at http://localhost:${PORT}/saml/metadata`);
  });
}
