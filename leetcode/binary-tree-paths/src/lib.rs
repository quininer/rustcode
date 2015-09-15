#![allow(dead_code)]

#[derive(Clone)]
pub struct TreeNode {
    pub val: usize,
    pub left: Option<Box<TreeNode>>,
    pub right: Option<Box<TreeNode>>
}

pub fn treepaths(tree: Box<TreeNode>) -> Vec<String> {
    let mut paths = vec![];
    let root = format!("{}", &tree.val);

    if (&tree).left.is_none() && (&tree).right.is_none() {
        paths.push(root);
    } else {
        if (&tree).left.is_some() {
            for p in treepaths(tree.clone().left.unwrap()) {
                paths.push(format!("{}->{}", root, p));
            };
        };
        if (&tree).right.is_some() {
            for p in treepaths(tree.clone().right.unwrap()) {
                paths.push(format!("{}->{}", root, p));
            };
        };
    };

    paths
}

#[test]
fn it_works() {
    assert_eq!(treepaths(Box::new(TreeNode {
        val: 1,
        left: Some(Box::new(TreeNode {
            val: 2,
            left: None,
            right: Some(Box::new(TreeNode {
                val: 5,
                left: None,
                right: None
            }))
        })),
        right: Some(Box::new(TreeNode {
            val: 3,
            left: None,
            right: None
        }))
    })), vec!["1->2->5", "1->3"]);
}
