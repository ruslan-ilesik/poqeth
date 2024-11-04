import pandas as pd
import numpy as np
from sklearn.preprocessing import PolynomialFeatures
from sklearn.linear_model import LinearRegression
from sklearn.metrics import mean_absolute_error, mean_squared_error
import os
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Load and prepare data
script_dir = os.path.dirname(os.path.abspath(__file__))
df = pd.read_csv(os.path.join(script_dir, 'results.csv'))
df = df[df['verify_value'] != 'not found']
df = df.astype({'h': int, 'd': int, 'a': int, 'k': int, 'verify_value': int})

# Define features and target
X = df[['h', 'd', 'a', 'k']].values
y = df['verify_value'].values

# Polynomial transformation with a chosen degree
degree = 12
poly = PolynomialFeatures(degree)
X_poly = poly.fit_transform(X)

# Fit a linear model on the polynomial features
model = LinearRegression()
model.fit(X_poly, y)

# Get the polynomial feature names
feature_names = poly.get_feature_names_out(['h', 'd', 'a', 'k'])

# Print the approximation formula
formula = "verify_value ≈ "
for coef, name in zip(model.coef_, feature_names):
    formula += f"{coef:.2f}*{name} + "
formula += f"{model.intercept_:.2f}"
print("Approximation Formula:")
print(formula)

# Calculate and print the approximation error metrics
y_pred = model.predict(X_poly)
mae = mean_absolute_error(y, y_pred)
mse = mean_squared_error(y, y_pred)
rmse = np.sqrt(mse)

print("\nApproximation Error Metrics:")
print(f"Mean Absolute Error (MAE): {mae:.2f}")
print(f"Mean Squared Error (MSE): {mse:.2f}")
print(f"Root Mean Squared Error (RMSE): {rmse:.2f}")

# Plotting - Pairwise Scatter Plots with Actual vs. Predicted verify_value
fig, axes = plt.subplots(2, 2, figsize=(14, 12))
parameters = ['h', 'd', 'a', 'k']
for i, param in enumerate(parameters):
    ax = axes[i//2, i%2]
    ax.scatter(df[param], y, label="Actual", color="blue", alpha=0.6)
    ax.scatter(df[param], y_pred, label="Predicted", color="red", alpha=0.6)
    ax.set_xlabel(param)
    ax.set_ylabel('verify_value')
    ax.legend()
    ax.set_title(f"Actual vs. Predicted verify_value for {param}")

plt.tight_layout()
plt.show()

# 3D Plot with Three Parameters (h, d, a) and verify_value as color
fig = plt.figure(figsize=(10, 8))
ax = fig.add_subplot(111, projection='3d')

# Plot actual data points
sc = ax.scatter(df['h'], df['d'], df['a'], c=y, cmap='viridis', marker='o', label="Actual", alpha=0.6)
cb = plt.colorbar(sc, ax=ax, label="Actual verify_value")
cb.set_label('Actual verify_value')

# Plot predicted data points
sc_pred = ax.scatter(df['h'], df['d'], df['a'], c=y_pred, cmap='plasma', marker='^', label="Predicted", alpha=0.6)
cb_pred = plt.colorbar(sc_pred, ax=ax, label="Predicted verify_value")
cb_pred.set_label('Predicted verify_value')

ax.set_xlabel('h')
ax.set_ylabel('d')
ax.set_zlabel('a')
ax.legend()
ax.set_title("3D Scatter Plot of Actual vs. Predicted verify_value")
plt.show()

# Plotting the generated polynomial function
h_range = np.linspace(df['h'].min(), df['h'].max(), 30)
d_range = np.linspace(df['d'].min(), df['d'].max(), 30)
a_range = np.linspace(df['a'].min(), df['a'].max(), 30)
k_value = df['k'].median()  # Choose a fixed value for k

# Create a mesh grid
H, D, A = np.meshgrid(h_range, d_range, a_range)

# Flatten the grid for predictions
grid_points = np.array([H.ravel(), D.ravel(), A.ravel(), np.full(H.size, k_value)]).T

# Transform the grid points to polynomial features
grid_points_poly = poly.transform(grid_points)

# Predict verify_value for the grid points
predicted_values = model.predict(grid_points_poly)

# Reshape the predicted values back to the mesh grid shape
Predicted = predicted_values.reshape(H.shape)

# 3D surface plot for (h, d, a) while keeping k fixed
fig = plt.figure(figsize=(12, 10))
ax = fig.add_subplot(111, projection='3d')
surf = ax.plot_surface(H[:, :, 0], D[:, :, 0], Predicted[:, :, 0], cmap='viridis', alpha=0.8)

# Add color bar to indicate meaning of colors
cb = fig.colorbar(surf, ax=ax, label='Predicted verify_value')
cb.set_label('Predicted verify_value')

ax.set_xlabel('h')
ax.set_ylabel('d')
ax.set_zlabel('Predicted verify_value')
ax.set_title('Generated Polynomial Function (h, d; a=mean; k=median)')
plt.show()

# Calculate global vmin and vmax for consistency
vmin = predicted_values.min()
vmax = predicted_values.max()

# Plotting for all combinations of parameters
def plot_surface(ax, param1, param2, fixed_param, fixed_value, title, vmin, vmax):
    range1 = np.linspace(df[param1].min(), df[param1].max(), 30)
    range2 = np.linspace(df[param2].min(), df[param2].max(), 30)

    # Create a mesh grid
    P1, P2 = np.meshgrid(range1, range2)

    # Prepare the grid points for predictions
    grid_points = np.array([P1.ravel(), P2.ravel(), np.full(P1.size, fixed_value[0]), np.full(P1.size, fixed_value[1])]).T
    grid_points_poly = poly.transform(grid_points)

    # Predict verify_value for the grid points
    predicted_values = model.predict(grid_points_poly)

    # Reshape the predicted values back to the mesh grid shape
    Predicted = predicted_values.reshape(P1.shape)

    # Create the surface plot
    surf = ax.plot_surface(P1, P2, Predicted, cmap='viridis', alpha=0.8, vmin=vmin, vmax=vmax)
    
    # Add color bar to indicate meaning of colors
    cb = fig.colorbar(surf, ax=ax, label='Predicted verify_value', pad=0.1)
    cb.set_label('Predicted verify_value')

    ax.set_xlabel(param1)
    ax.set_ylabel(param2)
    ax.set_zlabel('Predicted verify_value')
    ax.set_title(title)

# Create subplots for each combination of three parameters
fig = plt.figure(figsize=(18, 14))

# Plot surfaces for each combination
ax1 = fig.add_subplot(221, projection='3d')
plot_surface(ax1, 'h', 'd', ['a', 'k'], [df['a'].mean(), df['k'].median()], 'Generated Function (h, d; a=mean; k=median)', vmin, vmax)

ax2 = fig.add_subplot(222, projection='3d')
plot_surface(ax2, 'h', 'a', ['d', 'k'], [df['d'].median(), df['k'].median()], 'Generated Function (h, a; d=median; k=median)', vmin, vmax)

ax3 = fig.add_subplot(223, projection='3d')
plot_surface(ax3, 'd', 'a', ['h', 'k'], [df['h'].median(), df['k'].median()], 'Generated Function (d, a; h=median; k=median)', vmin, vmax)

ax4 = fig.add_subplot(224, projection='3d')
plot_surface(ax4, 'h', 'k', ['d', 'a'], [df['d'].median(), df['a'].mean()], 'Generated Function (h, k; d=median; a=mean)', vmin, vmax)

plt.tight_layout()
plt.show()
    