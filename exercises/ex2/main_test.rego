package ex2

# TODO: Write your test

test_can_attend_teenager_in_tokyo {
    input := {
        "age": 19,
        "region": "Tokyo"
    }
    can_attend with input as input
}

test_can_attend_adult_in_osaka {
    input := {
        "age": 35,
        "region": "Osaka"
    }
    can_attend with input as input
}

test_cannot_attend_teenager_in_kyoto {
    input := {
        "age": 17,
        "region": "Kyoto"
    }
    not can_attend with input as input
}

test_cannot_attend_adult_in_kyoto {
    input := {
        "age": 25,
        "region": "Kyoto"
    }
    not can_attend with input as input
}

test_cannot_attend_child_in_tokyo {
    input := {
        "age": 10,
        "region": "Tokyo"
    }
    not can_attend with input as input
}
