import re

def get_instances(name, conn):
    filter_ = re.compile(name)

    instances = []

    for reservation in conn.get_all_instances():
        instances.extend(reservation.instances)

    instances = [instance for instance in instances if
                    filter_.match(instance.tags.get('Name', ''))]

    instances = [instance for instance in instances if instance.vpc_id is None]

    linked_instances = conn.get_all_classic_link_instances()

    return list(set(all_instances) - set(linked_instances))

