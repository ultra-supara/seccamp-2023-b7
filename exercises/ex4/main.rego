package ex4

# denyをSetとして定義
deny[msg] {
    # env=productionのタグがあるインスタンスを取得
    prod_instance := input.Reservations[_].Instances[_]
    contains_tag(prod_instance.Tags, "env", "production")

    # t2.nanoまたはt2.microのインスタンスタイプを持つインスタンスを取得
    prod_instance.InstanceType == "t2.nano"
    msg := sprintf("instance %v has bad instanceType", [prod_instance.InstanceId])
}

deny[msg] {
    # env=productionのタグがあるインスタンスを取得
    prod_instance := input.Reservations[_].Instances[_]
    contains_tag(prod_instance.Tags, "env", "production")

    # t2.microのインスタンスタイプを持つインスタンスを取得
    prod_instance.InstanceType == "t2.micro"
    msg := sprintf("instance %v has bad instanceType", [prod_instance.InstanceId])
}

deny[msg] {
    # env=stagingのタグがあるインスタンスを取得
    staging_instance := input.Reservations[_].Instances[_]
    contains_tag(staging_instance.Tags, "env", "staging")

    # t2.nanoまたはt2.micro以外のインスタンスタイプを持つインスタンスを取得
    not staging_instance.InstanceType == "t2.nano"
    not staging_instance.InstanceType == "t2.micro"
    msg := sprintf("instance %v has bad instanceType", [staging_instance.InstanceId])
}

# タグのキーと値をチェックするヘルパー関数
contains_tag(tags, key, value) {
    tag := tags[_]
    tag.Key == key
    tag.Value == value
}
