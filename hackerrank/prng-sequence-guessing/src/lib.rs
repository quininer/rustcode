pub mod prng;

#[test]
fn test() {
    let mut input = include_str!("input.txt").lines();

    macro_rules! next {
        ( $input:expr ) => {
            $input.next()
                .and_then(|r| r.parse().ok())
                .unwrap()
        }
    }

    let result = (0..next!(input)).map(|_| {
        let (start, end) = input.next()
            .map(|r| r.split_whitespace())
            .map(|mut n| (next!(n), next!(n)))
            .unwrap();

        let values: Vec<usize> = (0..10)
            .map(|_| next!(input))
            .collect();

        (start..end).find(|&s| {
            prng::set_seed(s);

            (0..10)
                .map(|_| prng::next_int(1000))
                .zip(values.iter())
                .all(|(x, &y)| x == y)
        })
            .map(|s| (
                s,
                (0..10)
                    .map(|_| prng::next_int(1000))
                    .collect()
            ))
            .unwrap()
    })
        .collect::<Vec<(u64, Vec<usize>)>>();

    assert_eq!(
        (1374037200, vec![877, 633, 491, 596, 839, 875, 923, 461, 27, 826]),
        result[0]
    );
    assert_eq!(
        (1374037459, vec![101, 966, 573, 339, 784, 718, 949, 934, 62, 368]),
        result[1]
    );
}
