extern crate delete_node_in_a_linked_list;

use delete_node_in_a_linked_list::LinkedList;

fn linked2vec(mut linked: Box<LinkedList>) -> Vec<usize> {
    let mut list: Vec<usize> = vec![linked.val];

    while linked.next.is_some() {
        linked = linked.next.unwrap();
        list.push(linked.val);
    };

    list
}

#[allow(dead_code)]
fn is_palindrome(linked: Box<LinkedList>) -> bool {
    let mut rlist = linked2vec(linked.clone());
    let list = rlist.clone();
    rlist.reverse();

    list == rlist
}

#[test]
fn it_works() {
    assert!(is_palindrome(Box::new(LinkedList {
        val: 1,
        next: Some(Box::new(LinkedList {
            val: 2,
            next: Some(Box::new(LinkedList {
                val: 1,
                next: None
            }))
        }))
    })));
}
