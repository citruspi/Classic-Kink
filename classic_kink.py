import boto.ec2
import boto.vpc
import re
import sys
from classic_kink.security_groups import resolve_dependencies, diff, get, for_instances
from classic_kink.instances import get_instances

conn = boto.ec2.connect_to_region(sys.argv[1])

VPC_ID = sys.argv[3]

ignore = []

instances = get_instances(sys.argv[2], conn)
all_security_groups = for_instances(instances, ignore=ignore)
vpc_security_group_ids = {}

all_security_groups = resolve_dependencies(security_groups=all_security_groups,
                                            conn=conn, ignore=ignore)

for security_group in all_security_groups:

    print 'Checking if %s exists' % (security_group)

    group = get(security_group, conn, vpc_id=VPC_ID)

    if group is None:
        group = conn.create_security_group(security_group, security_group,
                                            vpc_id=VPC_ID)

    vpc_security_group_ids[security_group] = group.id

for security_group in all_security_groups:

    vpc_edition = get(security_group, conn, vpc_id=VPC_ID)
    classic_edition = get(security_group, conn)

    new_rules = diff(classic_edition, vpc_edition, ignore=ignore)

    for rule in new_rules:
        params = {
            'ip_protocol': rule['ip_protocol'],
            'from_port': rule['from_port'],
            'to_port': rule['to_port'],
        }

        try:
            source_group = get(rule['group'], conn, vpc_id=VPC_ID)

            params['src_group'] = source_group
        except KeyError:
            params['cidr_ip'] = rule['cidr_ip']

        vpc_edition.authorize(**params)

vconn = boto.vpc.connect_to_region(sys.argv[1])

for instance in instances:
    security_group_ids = [vpc_security_group_ids[group.name] for group in
                            instance.groups]

    vconn.attach_classic_link_vpc(VPC_ID, instance.id, security_group_ids)
