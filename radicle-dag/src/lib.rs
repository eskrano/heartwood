use std::{
    collections::{HashMap, HashSet},
    fmt,
    hash::Hash,
};

/// A node in the graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node<K: Eq + Hash, V> {
    value: V,
    dependencies: HashSet<K>,
}

/// A directed acyclic graph.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dag<K: Eq + Hash, V> {
    graph: HashMap<K, Node<K, V>>,
    tips: HashSet<K>,
    roots: HashSet<K>,
}

impl<K: Eq + Copy + Hash + fmt::Debug, V> Dag<K, V> {
    /// Create a new empty DAG.
    pub fn new() -> Self {
        Self {
            graph: HashMap::new(),
            tips: HashSet::new(),
            roots: HashSet::new(),
        }
    }

    /// Add a node to the graph.
    pub fn node(&mut self, key: K, value: V) -> Option<Node<K, V>> {
        self.tips.insert(key);
        self.roots.insert(key);
        self.graph.insert(
            key,
            Node {
                value,
                dependencies: HashSet::new(),
            },
        )
    }

    /// Add a dependency from one node to the other.
    pub fn dependency(&mut self, from: &K, to: K) {
        if let Some(node) = self.graph.get_mut(from) {
            node.dependencies.insert(to);
            self.tips.remove(&to);
            self.roots.remove(from);
        }
    }

    /// Get a node.
    pub fn get(&self, key: &K) -> Option<&Node<K, V>> {
        self.graph.get(key)
    }

    /// Get the graph's root nodes, ie. nodes which don't depend on other nodes.
    pub fn roots(&self) -> impl Iterator<Item = (&K, &Node<K, V>)> + '_ {
        self.roots
            .iter()
            .filter_map(|k| self.graph.get(k).map(|n| (k, n)))
    }

    /// Get the graph's tip nodes, ie. nodes which aren't depended on by other nodes.
    pub fn tips(&self) -> impl Iterator<Item = (&K, &Node<K, V>)> + '_ {
        self.tips
            .iter()
            .filter_map(|k| self.graph.get(k).map(|n| (k, n)))
    }

    /// Return a topological ordering of the graph's nodes, using the given RNG.
    /// Graphs with more than one partial order will return an arbitrary topological ordering.
    ///
    /// Calling this function over and over will eventually yield all possible orderings.
    pub fn topological(&self, rng: fastrand::Rng) -> Vec<K> {
        let mut order = Vec::new(); // Stores the topological order.
        let mut visited = HashSet::new(); // Nodes that have been visited.
        let mut keys = self.graph.keys().collect::<Vec<_>>();

        rng.shuffle(&mut keys);

        for node in keys {
            self.visit(node, &mut visited, &mut order);
        }
        order
    }

    /// Add nodes recursively to the topological order, starting from the given node.
    fn visit(&self, key: &K, visited: &mut HashSet<K>, order: &mut Vec<K>) {
        if visited.contains(key) {
            return;
        }
        visited.insert(*key);

        // Recursively visit all of the node's dependencies.
        if let Some(node) = self.graph.get(key) {
            for dependency in &node.dependencies {
                self.visit(dependency, visited, order);
            }
        }
        // Add the node to the topological order.
        order.push(*key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());

        dag.dependency(&0, 1);
        dag.dependency(&1, 0);

        let sorted = dag.topological(fastrand::Rng::new());
        let expected: &[&[i32]] = &[&[0, 1], &[1, 0]];

        assert!(expected.contains(&sorted.as_slice()));
    }

    #[test]
    fn test_diamond() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.node(2, ());
        dag.node(3, ());

        dag.dependency(&1, 0);
        dag.dependency(&2, 0);
        dag.dependency(&3, 1);
        dag.dependency(&3, 2);

        assert_eq!(dag.tips().map(|(k, _)| *k).collect::<Vec<_>>(), vec![3]);
        assert_eq!(dag.roots().map(|(k, _)| *k).collect::<Vec<_>>(), vec![0]);

        // All of the possible sort orders for the above graph.
        let expected: &[&[i32]] = &[&[0, 1, 2, 3], &[0, 2, 1, 3]];
        let actual = dag.topological(fastrand::Rng::new());

        assert!(expected.contains(&actual.as_slice()), "{:?}", actual);
    }

    #[test]
    fn test_complex() {
        let mut dag = Dag::new();

        dag.node(0, ());
        dag.node(1, ());
        dag.node(2, ());
        dag.node(3, ());
        dag.node(4, ());
        dag.node(5, ());

        dag.dependency(&3, 2);
        dag.dependency(&1, 3);
        dag.dependency(&2, 5);
        dag.dependency(&0, 5);
        dag.dependency(&0, 4);
        dag.dependency(&1, 4);

        assert_eq!(
            dag.tips().map(|(k, _)| *k).collect::<HashSet<_>>(),
            HashSet::from_iter([1, 0])
        );
        assert_eq!(
            dag.roots().map(|(k, _)| *k).collect::<HashSet<_>>(),
            HashSet::from_iter([4, 5])
        );

        // All of the possible sort orders for the above graph.
        let expected = &[
            [4, 5, 0, 2, 3, 1],
            [4, 5, 2, 0, 3, 1],
            [4, 5, 2, 3, 0, 1],
            [4, 5, 2, 3, 1, 0],
            [5, 2, 3, 4, 0, 1],
            [5, 2, 3, 4, 1, 0],
            [5, 2, 4, 0, 3, 1],
            [5, 2, 4, 3, 0, 1],
            [5, 2, 4, 3, 1, 0],
            [5, 4, 0, 2, 3, 1],
            [5, 4, 2, 0, 3, 1],
            [5, 4, 2, 3, 0, 1],
            [5, 4, 2, 3, 1, 0],
        ];
        let rng = fastrand::Rng::new();
        let mut sorts = HashSet::new();

        while sorts.len() < expected.len() {
            sorts.insert(dag.topological(rng.clone()));
        }
        for e in expected {
            assert!(sorts.remove(e.to_vec().as_slice()));
        }
        assert!(sorts.is_empty());
    }
}
