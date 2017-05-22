#!/usr/bin/python3

"""
Script to update a lets encrypt SSL server on an EC2 instance that has
restricted access to the web server ports. This will temporarily open
the ports, then renew the cert, and then close the ports when it is done.
"""

import boto3
import configparser
import time, datetime
from OpenSSL import crypto as c

def log(msg):
    ts = str(datetime.datetime.now())

    print(ts + ': ' + msg)

def add_ingress_rule(security_group_id, cidr_ip, port, protocol):
    """
    Add an EC2 security group ingress rule
    """

    client = boto3.client('ec2')
    response = client.authorize_security_group_ingress(
        DryRun=False,
        GroupId=security_group_id,
        IpProtocol=protocol,
        FromPort=port,
        ToPort=port,
        CidrIp=cidr_ip
    )

    log("add ingress response: " + response)

def remove_ingress_rule(security_group_id, cidr_ip, port, protocol):
    """
    Remove an EC2 security group ingress rule
    """

    client = boto3.client('ec2')
    response = client.revoke_security_group_ingress(
        DryRun=False,
        GroupId=security_group_id,
        IpProtocol=protocol,
        FromPort=port,
        ToPort=port,
        CidrIp=cidr_ip
    )

    log("remove ingress response: " + response)


def ready_for_renewal(domain):
    crt_file = open('/etc/letsencrypt/live/gitlab.pdev.io/cert.pem', 'rt').read()
    cert = c.load_certificate(c.FILETYPE_PEM, crt_file)

    expire_date = datetime.datetime.strptime(cert.get_notAfter().decode("utf-8"),"%Y%m%d%H%M%SZ")
    today = datetime.datetime.today()
    margin = datetime.timedelta(days = 29)

    if expire_date < today + margin:
        log("Cert expiring in less than 30 days: " + str(expire_date))
        return True

    log("Cert not expiring in less than 30 days: " + str(expire_date))
    return False



def renew_cert(security_group_id, verification_port,  domain):
    """
    Renew the SSL  cert for the specified domain
    """

    log("Executing renew script for " + domain + " on security group " + security_group_id + ", port " + verification_port)

    # Add the global allow rule
    add_ingress_rule(security_group_id, '0.0.0.0/0', verification_port, 'tcp')

    # Sleep to make sure the security group update takes effect
    log("Sleeping for 15 seconds to allow security group to update...")
    time.sleep(15)

    # Renew the certificate
    # -n = non-interactive
    # -d = comma delimited list of domains to renew
    result = subprocess.run(["/usr/bin/certbot", "-n", "--cert-name", domain, 'renew'], stdout=subprocess.PIPE)
    log(result.stdout)

    # Remove the global allow rule
    remove_ingress_rule(security_group_id, '0.0.0.0/0', verification_port, 'tcp')



if __name__ == '__main__':
     config = configparser.ConfigParser()
     config.read('config.ini')

     for domain in config['Domains']:
         log("Processing domain: " + domain)

         domain_config = config[domain]
         security_group_id = domain_config['SecurityGroupId']
         verification_port = domain_config['VerificationPort']

         if ready_for_renewal(domain):
             renew_cert(security_group_id, verification_port, domain)
