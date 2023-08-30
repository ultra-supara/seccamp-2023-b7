package ex5

# denyをSetとして定義
deny[sg_id] = msg {
    # セキュリティグループを取得
    sg := input.SecurityGroups[_]
    permission := sg.IpPermissions[_]

    # インターネット全体に公開されているか確認
    ip_range := permission.IpRanges[_]
    ip_range.CidrIp == "0.0.0.0/0"

    # プロトコルがTCPで、許可されているポートが443以外の場合
    permission.IpProtocol == "tcp"
    not is_valid_port(permission.FromPort, permission.ToPort)

    # 違反メッセージを作成
    sg_id := sg.GroupId
    msg = sprintf("Security group %v allows TCP traffic on port 443", [sg.GroupId])
}

# ポート443のみが有効かどうかを確認するヘルパー関数
is_valid_port(from, to) {
    from == 443
    to == 443
}
