package ex6

import input.instances
import input.security_groups

# failedルールの結果に基づいて動作するviolatedルール。
# failedルールが1つ以上のメッセージを返す場合、violatedルールも動作する。
violated {
    count(failed) > 0
    print(failed)
}

# env=productionタグがついたインスタンスを検出するルール
production_instance(instance) {
    instance = instances.Reservations[_].Instances[_]
    tag := instance.Tags[_]
    tag.Key == "env"
    tag.Value == "production"
}

# 特定のポートで全体のアクセスを許可するセキュリティグループを検出するルール
global_access(sg, port) {
    rule := sg.IpPermissions[_]
    rule.FromPort <= port
    rule.ToPort >= port
    cidr := rule.IpRanges[_].CidrIp
    cidr == "0.0.0.0/0"
}

# env=productionタグがついているインスタンスで、443ポートがインターネットに公開されていない場合のルール
failed[msg] {
    instance := instances.Reservations[_].Instances[_]
    production_instance(instance)
    sg := security_groups.SecurityGroups[_]
    group := instance.NetworkInterfaces[_].Groups[_]
    group.GroupId == sg.GroupId
    not global_access(sg, 443)
    msg := sprintf("Instance ID: %v , Security Group ID: %v does not have port 443 open to the internet.", [instance.InstanceId, sg.GroupId])
}

# env=productionタグがついているインスタンスで、443以外のポートがインターネットに公開されている場合のルール
failed[msg] {
    instance := instances.Reservations[_].Instances[_]
    production_instance(instance)
    sg := security_groups.SecurityGroups[_]
    group := instance.NetworkInterfaces[_].Groups[_]
    group.GroupId == sg.GroupId
    port := sg.IpPermissions[_].FromPort
    port != 443
    global_access(sg, port)
    msg := sprintf("Instance ID: %v , Security Group ID: %v has port %v open to the internet which is not allowed.", [instance.InstanceId, sg.GroupId, port])
}

# env=productionタグがついていないインスタンスで、任意のポートがインターネットに公開されている場合のルール
failed[msg] {
    instance := instances.Reservations[_].Instances[_]
    not production_instance(instance)
    sg := security_groups.SecurityGroups[_]
    group := instance.NetworkInterfaces[_].Groups[_]
    group.GroupId == sg.GroupId
    port := sg.IpPermissions[_].FromPort
    global_access(sg, port)
    msg := sprintf("Instance ID: %v , Security Group ID: %v has ports open to the internet which is not allowed for non-production instances.", [instance.InstanceId, sg.GroupId])
}
