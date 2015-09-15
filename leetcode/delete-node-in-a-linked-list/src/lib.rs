#![allow(dead_code)]

#[derive(Clone)]
struct LinkedList {
    key: usize,
    next: Option<Box<LinkedList>>
}

fn delete_node(mut list: Box<LinkedList>, key: usize) -> Option<Box<LinkedList>> {
    if (&list).key == key {
        return list.next;
    };

    if (&list).next.is_some() {
        list.next = delete_node(list.clone().next.unwrap(), key);
    };

    Some(list)
}

fn listpath(list: Box<LinkedList>) -> String {
    if (&list).next.is_none() {
        format!("{}", (&list).key)
    } else {
        format!("{}->{}", (&list).key, listpath(list.clone().next.unwrap()))
    }
}

#[test]
fn it_works() {
    let list = delete_node(Box::new(LinkedList {
        key: 1,
        next: Some(Box::new(LinkedList {
            key: 2,
            next: Some(Box::new(LinkedList {
                key: 3,
                next: Some(Box::new(LinkedList {
                    key: 4,
                    next: None
                }))
            }))
        }))
    }), 3);

    assert_eq!(listpath(list.unwrap()), "1->2->4");
}
