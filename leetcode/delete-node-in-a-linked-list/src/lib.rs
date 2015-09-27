#![allow(dead_code)]

#[derive(Clone)]
pub struct LinkedList {
    pub val: usize,
    pub next: Option<Box<LinkedList>>
}

fn delete_node(mut linked: Box<LinkedList>, val: usize) -> Option<Box<LinkedList>> {
    if (&linked).val == val {
        return linked.next;
    };

    if (&linked).next.is_some() {
        linked.next = delete_node(linked.clone().next.unwrap(), val);
    };

    Some(linked)
}

fn listpath(linked: Box<LinkedList>) -> String {
    if (&linked).next.is_none() {
        format!("{}", (&linked).val)
    } else {
        format!("{}->{}", (&linked).val, listpath(linked.clone().next.unwrap()))
    }
}

#[test]
fn it_works() {
    let linked = delete_node(Box::new(LinkedList {
        val: 1,
        next: Some(Box::new(LinkedList {
            val: 2,
            next: Some(Box::new(LinkedList {
                val: 3,
                next: Some(Box::new(LinkedList {
                    val: 4,
                    next: None
                }))
            }))
        }))
    }), 3);

    assert_eq!(listpath(linked.unwrap()), "1->2->4");
}
