package ex3

import data.users
import data.resources

# ownerはすべてのアクションを許可
allow {
    is_owner
}

# viewerの権限がある場合は読み取りを許可
allow {
    action_matches["read"]
    has_permission["viewer"]
}

# editorの権限がある場合は読み取りと書き込みを許可
allow {
    action_matches[_]
    has_permission["editor"]
}

# リソースのオーナーかどうかをチェック
is_owner {
    resource := resources[_]
    resource.id == input.resource
    resource.owner == input.user
}

# actionが読み取りまたは書き込みに一致するかをチェック
action_matches[action] {
    action = input.action
    ["read", "write"][_]
}

# ユーザーが指定された権限を持っているかどうかをチェック
has_permission[permission] {
    resource := resources[_]
    resource.id == input.resource
    user := users[_]
    user.id == input.user
    permission = resource.permissions[user.role]
}
