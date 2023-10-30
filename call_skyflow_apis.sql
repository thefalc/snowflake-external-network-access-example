-- Define variables for the auth domain, vault domain, vault ID, and vault URL
SET auth_domain = 'manage.skyflowapis.com';
SET vault_domain = '<REPLACE WITH VAULT DOMAIN>';
SET vault_url = 'https://' || $vault_domain || '/v1/vaults/<REPLACE WITH VAULT ID>';

-- Store Skyflow service account key with Snowflake Secrets Manager
CREATE OR REPLACE SECRET skyflow_vault_secret
    TYPE = GENERIC_STRING
    SECRET_STRING = '<REPLACE WITH SERVICE ACCOUNT KEY>';

-- Grant access to the Skyflow API endpoints for authentication and vault APIs
CREATE OR REPLACE NETWORK RULE skyflow_apis_network_rule
 MODE = EGRESS
 TYPE = HOST_PORT
 VALUE_LIST = ($auth_domain, $vault_domain);

-- Create an integration using the network rule and secret
CREATE OR REPLACE EXTERNAL ACCESS INTEGRATION skyflow_external_access_integration
 ALLOWED_NETWORK_RULES = (skyflow_apis_network_rule)
 ALLOWED_AUTHENTICATION_SECRETS = (skyflow_vault_secret)
 ENABLED = true;

-- Create a UDF to de-identify a single value
CREATE OR REPLACE FUNCTION skyflow_deidentify(vault_url text, table_name text, column_name text, value text)
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = 3.8
HANDLER = 'skyflow_deidentify'
EXTERNAL_ACCESS_INTEGRATIONS = (skyflow_external_access_integration)
PACKAGES = ('pyjwt', 'cryptography', 'requests', 'simplejson')
SECRETS = ('cred' = skyflow_vault_secret)
AS
$$
import _snowflake
import simplejson as json
import jwt
import requests 
import time

def generate_auth_token():
    credentials = json.loads(_snowflake.get_generic_secret_string('cred'), strict=False)
    
    # Create the claims object with the data in the creds object
    claims = {
       "iss": credentials["clientID"],
       "key": credentials["keyID"], 
       "aud": credentials["tokenURI"], 
       "exp": int(time.time()) + (3600), # JWT expires in Now + 60 minutes
       "sub": credentials["clientID"], 
    }
    # Sign the claims object with the private key contained in the creds object
    signedJWT = jwt.encode(claims, credentials["privateKey"], algorithm='RS256')

    body = {
       'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
       'assertion': signedJWT,
    }
    tokenURI = credentials["tokenURI"]

    session = requests.Session()
    r = session.post(tokenURI, json=body)
    auth = json.loads(r.text)
    
    return auth["accessToken"]

def skyflow_deidentify(vault_url, table_name, column_name, value):
    auth_token = generate_auth_token()
  
    body = {
       "tokenization": True,
       "records": [
           {
               "fields": {
                   column_name: value
               }
           }
       ]
    }

    url = vault_url + "/" + table_name
    headers = {
        "Authorization": "Bearer " + auth_token
    }

    session = requests.Session()
    response = session.post(url, json=body, headers=headers)
    
    response_as_json = json.loads(response.text)
    
    return response_as_json["records"][0]["tokens"][column_name]
$$;

-- Example of using the de-identification UDF
-- Insert my name into my Skyflow vault and store the de-identified data in Snowflake
INSERT INTO customers (
    name
)
SELECT skyflow_deidentify($vault_url, 'persons', 'name', 'Sean Falconer') as name;

-- Check Snowflake to see that the customers table was updated
SELECT name FROM customers;

-- Create a UDF to re-identify a de-identified value
CREATE OR REPLACE FUNCTION skyflow_reidentify(vault_url text, value text)
RETURNS STRING
LANGUAGE PYTHON
RUNTIME_VERSION = 3.8
HANDLER = 'skyflow_reidentify'
EXTERNAL_ACCESS_INTEGRATIONS = (skyflow_external_access_integration)
PACKAGES = ('pyjwt', 'cryptography', 'requests', 'simplejson')
SECRETS = ('cred' = skyflow_vault_secret)
AS
$$
import _snowflake
import simplejson as json
import jwt
import requests 
import time

def generate_auth_token():
    credentials = json.loads(_snowflake.get_generic_secret_string('cred'), strict=False)
    
    # Create the claims object with the data in the creds object
    claims = {
       "iss": credentials["clientID"],
       "key": credentials["keyID"], 
       "aud": credentials["tokenURI"], 
       "exp": int(time.time()) + (3600), # JWT expires in Now + 60 minutes
       "sub": credentials["clientID"], 
    }
    # Sign the claims object with the private key contained in the creds object
    signedJWT = jwt.encode(claims, credentials["privateKey"], algorithm='RS256')

    body = {
       'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
       'assertion': signedJWT,
    }
    tokenURI = credentials["tokenURI"]

    session = requests.Session()
    r = session.post(tokenURI, json=body)
    auth = json.loads(r.text)
    
    return auth["accessToken"]

def skyflow_reidentify(vault_url, value):
    auth_token = generate_auth_token()
  
    body = {
       "detokenizationParameters": [
           {
               "token": value
           }
       ]
    }

    url = vault_url + "/detokenize"
    headers = {
        "Authorization": "Bearer " + auth_token
    }

    session = requests.Session()
    response = session.post(url, json=body, headers=headers)
    
    response_as_json = json.loads(response.text)

    return response_as_json["records"][0]["value"]
$$;

-- Example of using the re-identification UDF
-- Re-identify all names in the customer table
with customer_list as (
    select skyflow_reidentify($vault_url, name) from customers
)
select * from customer_list;