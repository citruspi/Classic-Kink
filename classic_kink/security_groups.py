import re

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
