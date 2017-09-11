import requests
import json
import os

TEMP_PUBKEY_GEN = '/tmp/public_key.pub'
keystone_username = "cloudify"
keystone_password = "cloudify"
tenant_name = "mano"
keystone_url = "http://10.84.20.3:5000/v3"
nova_url = "http://10.84.20.3:8774/v2.1"
neutron_url = "http://10.84.20.3:9696"
network_name = "cloudify-management-network"
private_key_path = "/tmp/cloudify"
keypair_name = "cloudify_manager"

keystone_data_v2 = {"auth": {"tenantName": "{0}".format(tenant_name),
                             "passwordCredentials":
                             {"username": "{0}".format(keystone_username),
                              "password": "{0}".format(keystone_password)}}}
keystone_data_v3 = {
  "auth": {
    "identity": {
      "methods": ["password"],
      "password": {
        "user": {
          "name": "{0}".format(keystone_username),
          "domain": {"name": "default"},
          "password": "{0}".format(keystone_password)
        }
      }
    },
    "scope": {
      "project": {
        "name": "{0}".format(tenant_name),
        "domain": {"name": "default"}
      }
    }
  }
}


def check_endpoint_exist(endpoints, url):
    """
    Checking whether url exists in the project endpoints 
    :param endpoints: list of the project endpoints in openstack system
                     (For Ex: list of nova endpoints)
    :param url: the url that you want to check whether it in the endpoints list or not
    :return: if the url exists in the endpoints list return True otherwise, return False
    """
    for endpoint in endpoints:
        if url in endpoint.values():
            print("yes it is true")
            return True
    return False


def filter_endpoints(openstack_endpoints):
    """
    Filtering nova endpoints and neutron endpoints
    :param openstack_endpoints: Containing the Whole project endpoints in openstack system
    :return: if nova endpoints and neutron endpoints exist, return their endpoints
             otherwise return none
    """
    nova_endpoints = None
    neutron_endpoints = None
    for endpoints in openstack_endpoints:
        if endpoints["name"] == "nova":
            nova_endpoints = endpoints["endpoints"]
        if endpoints["name"] == "neutron":
            neutron_endpoints = endpoints["endpoints"]
    return nova_endpoints, neutron_endpoints


def get_api_version(arr_url):
    """
    :param arr_url:  List of keystone url after performed method keystone_url.split("")
    :return: Keystone Version(for Ex: return v2.0 or v3)
    """
    return arr_url[-1]


def validating_openstack_parameters():
    """
    Comparing input parameters with Openstack authentication parameters(username,password,url).
    If input parameters match all Openstack authentication parameters then return True and keystone_token.
    Otherwise, return False and empty string.
    :return: True and keystone_token or False and empty string.
    """
    keystone_headers = {"Content-Type": "application/json"}
    separated_url = keystone_url.split("/")
    if get_api_version(separated_url) == "v2.0":
        keystone_api_request = requests.post(keystone_url+"/tokens",
                                             data=json.dumps(keystone_data_v2),
                                             headers=keystone_headers)
        if keystone_api_request.status_code != 200:
            print("Something wrong with your keystone information"
                  "please check it carefully")
            return False, ""

        keystone_token = json.loads(keystone_api_request.content)["access"]["token"]["id"]
        openstack_endpoints = json.loads(keystone_api_request.content)["access"]["serviceCatalog"]
        nova_endpoints, neutron_endpoints = filter_endpoints(openstack_endpoints)

        if not (check_endpoint_exist(nova_endpoints, nova_url) and
                check_endpoint_exist(neutron_endpoints, neutron_url)):
            print("Something wrong with your nova and neutron "
                  "information please check it carefully")
            return False, ""
        return True, keystone_token

    if get_api_version(separated_url) == "v3":
        keystone_api_request = requests.post(keystone_url + "/auth/tokens",
                                             data=json.dumps(keystone_data_v3),
                                             headers=keystone_headers)
        if keystone_api_request.status_code != 201:
            print("Something wrong with your keystone information"
                  "please check it carefully")
            return False, ""

        keystone_token = keystone_api_request.headers['X-Subject-Token']
        openstack_endpoints = json.loads(keystone_api_request.content)["token"]["catalog"]
        nova_endpoints, neutron_endpoints = filter_endpoints(openstack_endpoints)
        if not (check_endpoint_exist(nova_endpoints, nova_url) and
                check_endpoint_exist(neutron_endpoints, neutron_url)):
            print("Something wrong with your nova and neutron "
                  "information please check it carefully")
            return False, ""
        return True, keystone_token

    else:
        print("Something wrong with your keystone information"
              "please check it carefully")
        return False, ""


def check_network_exist(keystone_token):
    """
    Checking whether the input network name is matched one of the network name in openstack system.
    :param keystone_token: Token for authentication.
    :return: True if input network name was found, otherwise return False.
    """
    neutron_headers = {"X-Auth-Token": keystone_token}
    neutron_request_api = requests.get(neutron_url+"/v2.0/networks",
                                       headers=neutron_headers)
    neutron_networks = json.loads(neutron_request_api.content)['networks']
    for network in neutron_networks:
        if network_name in network.values():
            return True
    return False


def check_key_pair(keystone_token):
    """
    Firstly, Checking the keypair_name exists in the openstack system.
    After that, Checking, if cloudify manager can use the private key from private_key_path for 
    ssh to vm in openstack which has keypair is keypair_name.
    :param keystone_token: Token for authentication.
    :return: True if passed all the steps above and otherwise return False
    """
    KEY = 1
    nova_headers = {"X-Auth-Token": keystone_token}
    nova_request_api = \
        requests.get(nova_url + "/os-keypairs/{0}".format(keypair_name),
                     headers=nova_headers)
    if nova_request_api.status_code != 200:
        return False
    nova_public_keypair = json.loads(nova_request_api.content)["keypair"]["public_key"]
    nova_public_keypair = (nova_public_keypair.split())[KEY]
    os.system("ssh-keygen -f {0} -y > {1}".format(private_key_path, TEMP_PUBKEY_GEN))
    nova_convert_key = file(TEMP_PUBKEY_GEN, "r").read().split()[KEY]
    print(nova_convert_key)
    print(nova_public_keypair)
    if nova_convert_key == nova_public_keypair:
        return True
    return False


def main():
    authorization, keystone_token = validating_openstack_parameters()
    print(authorization, keystone_token)
    if authorization:
        if check_network_exist(keystone_token):
            print("yes it is true network")
        else:
            print("Something wrong with your network name "
                  "information, please check it carefully")
    if check_key_pair(keystone_token):
        print("yes it is true keypair")
    else:
        print("Something wrong with your keypair information,"
              "please check it carefully")


if __name__ == "__main__":
    main()