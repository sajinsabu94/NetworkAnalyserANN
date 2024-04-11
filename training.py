import pickle # used to save the model for further testing and use
import csv #python standard for csv work
import pyshark # tshark wrapper used to capture and parse packets
import time #allows for time be used
import datetime #allows for dates to be used
import pandas # data handler for input into Aritificial neural network
from timeit import default_timer as timer
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import numpy as np

def LabelEncoding(data): # encodes the categorical data within the csv used for training, turns the categorical values into integer values
    columnsToEncode = list(data.select_dtypes(include=['category', 'object']))  
    #print(data.dtypes) #Prints each columns d_type
    #print(columnsToEncode) #Prints categorical features
    le = LabelEncoder()
    for feature in columnsToEncode:
        try:
            data[feature] = le.fit_transform(data[feature])
            #print(data[feature])
        except:
            print ('error' + feature)
    return data
        
l_data = input("Name of CSV file : ")
from sklearn.neural_network import MLPClassifier #imports the neural network class from Sci-kit learn
mlp = MLPClassifier(hidden_layer_sizes=(100,100),activation='logistic', max_iter=1000, verbose=True, tol=0.00000001, early_stopping = True, shuffle = True) # Designates the setting of the model before training
#hidden_layer_sizes = array of the hidden layer of the network, (5) = one layer of 5 nodes, (5,5) = 2 layers, both with 5 nodes
#activation = activation function, 'logistic' is equivalent ot the sigmoid activation function
#max_iter = max3imum amoung of iterations that the model will do
#Verbose = whether the model prints the iteration and loss function per iteration
#tol = the decimal place the use wants the loss function to reach

data = pandas.read_csv(l_data, delimiter=',')# reads CSV
data = LabelEncoding(data) #Encodes the categorical data into int input data the model can use
#print("Encoded Data: ", "\n", data) # entire encoded block for testing and checking values
#print(data.keys())

X = data[['Highest Layer', 'Transport Layer', 'Source IP', 'Dest IP', 'Source Port', 'Dest Port','Packet Length', 'Packets/Time']] # Data used to train
#print ("Features: ", "\n", X)
y = data['target'] # targets for the MLP
#print ("Targets: ", "\n", y)

from sklearn.model_selection import train_test_split #Needed to split the data into the training and testing
from sklearn.preprocessing import StandardScaler #required to so that all the inputs are in a comparable range
X_train, X_test, y_train, y_test = train_test_split(X, y)
#print(type(X_train))
#scaler = StandardScaler()
#scaler.fit(X_train)
#X_train = scaler.transform(X_train)
#X_test = scaler.transform(X_test)
#print(X_train) # Training data (Features)
#print(X_test) # Testing data (features

start_time = timer()
mlp.fit(X_train, y_train) # fit is used to actually train the model
predictions = mlp.predict(X_test)
#print(predictions)
end_time = timer()
time_taken = end_time - start_time


N_TRAIN_SAMPLES = X_train.shape[0]
N_EPOCHS = 25
N_BATCH = 128
l = [0,1]
N_CLASSES = np.asarray(l)
scores_train = []
scores_test = []
epoch = 0
while epoch < N_EPOCHS:
	random_perm = np.random.permutation(X_train.shape[0])
	mini_batch_index = 0
	while True:
		# MINI-BATCH
		indices = random_perm[mini_batch_index:mini_batch_index + N_BATCH]
		mlp.partial_fit(X_train, y_train, N_CLASSES)
		mini_batch_index += N_BATCH

		if mini_batch_index >= N_TRAIN_SAMPLES:
			break
	scores_train.append(mlp.score(X_train, y_train))
	scores_test.append(mlp.score(X_test, y_test))
	epoch += 1
#print(scores_train)
plt.plot(scores_train, color='green', alpha=0.8, label='Train')
plt.plot(scores_test, color='magenta', alpha=0.8, label='Test')
plt.title("Accuracy over epochs", fontsize=14)
plt.xlabel('Epochs')
plt.legend(loc='upper left')
plt.show()

plt.ylabel('cost')
plt.xlabel('iterations')
plt.title("Learning rate =" + str(0.001))
plt.plot(mlp.loss_curve_)
plt.show()
#print("First 50 Predictions: ", "\n" ,mlp.predict(X_test)[0:50]) #Prints first 50 predictions
#print("First 50 Probabilities: ", "\n",mlp.predict_proba(X_test)[0:50])#Prints first 50 probabilities

print("Number of Iterations: ", mlp.n_iter_)
print(mlp.loss_)
hostile = 0
safe = 0
for check in predictions:
    if check == 1:
        hostile += 1
    else:
        safe += 1
print("Safe Packets: ", safe)
print("Hostile Packets: ", hostile)
print("Time Taken:", time_taken)

from sklearn.metrics import classification_report,confusion_matrix
print("Confusion Matrix: ", "\n", confusion_matrix(y_test,predictions))
print()

print ("Classification Report: ", "\n",  classification_report(y_test,predictions))
print()

#print("Model Coefficients (Weights): ", "\n", mlp.coefs_)
#print()
#print("Model Intercepts (Nodes): ", "\n", mlp.intercepts_)


filename = input("Filename for saving : ")
pickle.dump(mlp, open(filename, 'wb'))

