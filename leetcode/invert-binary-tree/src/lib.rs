#![allow(dead_code)]

extern crate binary_tree_paths;

use binary_tree_paths::TreeNode;

fn invert(mut tree: Box<TreeNode>) -> Box<TreeNode> {
    let left =
        if (&tree).right.is_some() {
            Some(invert(tree.clone().right.unwrap()))
        } else {
            None
        };
    let right =
        if (&tree).left.is_some() {
            Some(invert(tree.clone().left.unwrap()))
        } else {
            None
        };

    tree.left = left;
    tree.right = right;

    tree
}

#[test]
fn it_works() {
    use binary_tree_paths::treepaths;

    let tree = Box::new(TreeNode {
        val: 4,
        left: Some(Box::new(TreeNode {
            val: 2,
            left: Some(Box::new(TreeNode {
                val: 1,
                left: None,
                right: None
            })),
            right: Some(Box::new(TreeNode {
                val: 3,
                left: None,
                right: None
            }))
        })),
        right: Some(Box::new(TreeNode {
            val: 7,
            left: Some(Box::new(TreeNode {
                val: 6,
                left: None,
                right: None
            })),
            right: Some(Box::new(TreeNode {
                val: 9,
                left: None,
                right: None
            }))
        }))
    });
    let mut path1 = treepaths(tree.clone());
    let path2 = treepaths(invert(tree.clone()));
    path1.reverse();

    assert_eq!(path1, path2);
}
