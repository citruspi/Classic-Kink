import re
import itertools

def resolve_dependencies(security_groups, conn, ignore=None):

    ignore_map = {}

    if ignore is not None:
        for rule in ignore:
            ignore_map[rule] = re.compile(rule)

    complete = False

    while not complete:
        complete = True

        for group in security_groups:
            filters = {'group-name': group}
            response = conn.get_all_security_groups(filters=filters)

            group = [group for group in response if group.vpc_id is None][0]

            for rule in group.rules:
                for granted in rule.grants:
                    try:
                        discard = any([exp.match(granted.groupName) for exp in
                                                        ignore_map.values()])

                        if not discard:
                            if granted.groupName not in security_groups:
                                security_groups.append(granted.groupName)
                                complete = False
                    except AttributeError:
                        pass

    return security_groups

def diff(a, b, ignore=None):

    ignore_map = {}

    if ignore is not None:
        for rule in ignore:
            ignore_map[rule] = re.compile(rule)

    a_rules = []
    b_rules = []

    for group in [a, b]:
        for rule in group.rules:
            for granted in rule.grants:
                rule_params = {
                    'ip_protocol': rule.ip_protocol,
                    'from_port': rule.from_port,
                    'to_port': rule.to_port
                }

                try:
                    rule_params['group'] = granted.groupName
                    discard = any([exp.match(granted.groupName) for exp in
                                                        ignore_map.values()])
                except AttributeError:
                    rule_params['cidr_ip'] = granted.cidr_ip
                    discard = any([exp.match(granted.cidr_ip) for exp in
                                                        ignore_map.values()])

                if not discard:
                    if group == a: a_rules.append(rule_params)
                    elif group == b: b_rules.append(rule_params)

    return list(itertools.ifilterfalse(lambda x: x in a_rules, b_rules)) + \
           list(itertools.ifilterfalse(lambda x: x in b_rules, a_rules))

def for_instances(instances, ignore=None):

    ignore_map = {}

    if ignore is not None:
        for rule in ignore:
            ignore_map[rule] = re.compile(rule)

    security_groups = []

    for instance in instances:
        security.groups.extend([group.name for group in instance.groups])

    security_groups = list(set(security_groups))

    filter_ = lambda r: any([exp.match(r) for exp in ignore_map.values()])

    security_groups = [g for g in security_groups if not filter_(g)]

    return security_groups

def get(group, conn, vpc_id=None):

    result = None

    if vpc_id is None:
        filters = {'group-name': group}

        groups = conn.get_all_security_groups(filters=filters)
        groups = [group for group in groups if group.vpc_id is None]

        try:
            return groups[0]
        except IndexError:
            return None

    else:
        filters = {'group-name': group, 'vpc-id': vpc_id}

        groups = conn.get_all_security_groups(filters=filters)

        try:
            return groups[0]
        except IndexError:
            return None

