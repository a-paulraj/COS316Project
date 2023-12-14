import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import plot_tree
import matplotlib.pyplot as plt

# Load the Random Forest model from the pickle file
with open('RF.pkl', 'rb') as file:
    rf_model = pickle.load(file)

# Visualize individual trees in the Random Forest
n_trees_to_visualize = min(3, len(rf_model.estimators_))  # Adjust the number of trees to visualize if needed

for i in range(n_trees_to_visualize):
    tree = rf_model.estimators_[i]

    # Plot the tree with adjusted size
    plt.figure(figsize=(20, 10))
    plot_tree(tree, filled=True, feature_names=None, class_names=None, rounded=True, fontsize=10)
    plt.title(f'Tree {i+1} of Random Forest', fontsize=16)
    plt.show()
