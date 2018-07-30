
# coding: utf-8

# In[1]:


import pandas as pd


# ## Collection of Data

# In[2]:


legitimate_urls = pd.read_csv("legitimate-urls.csv")
phishing_urls = pd.read_csv("phishing-urls.csv")


# In[3]:


print(len(legitimate_urls))
print(len(phishing_urls))


# ## Data PreProcessing
# #### Data is in two data frames so we merge them to make one dataframe
# Note: two dataframes has same column names

# In[4]:


urls = legitimate_urls.append(phishing_urls)


# In[5]:


urls.head(5)


# In[6]:

print(len(urls))
print(urls.columns)


# #### Removing Unnecessary columns

# In[7]:


urls = urls.drop(urls.columns[[0,3,5]],axis=1)
print(urls.columns)

# #### Since we merged two dataframes top 1000 rows will have legitimate urls and bottom 1000 rows will have phishing urls. So if we split the data now and create a model for it will overfit or underfit so we need to shuffle the rows before splitting the data into training set and test set

# In[8]:


# shuffling the rows in the dataset so that when splitting the train and test set are equally distributed
urls = urls.sample(frac=1).reset_index(drop=True)


# #### Removing class variable from the dataset
urls_without_labels = urls.drop('label',axis=1)
urls_without_labels.columns
labels = urls['label']
#labels

# #### splitting the data into train data and test data
import random
random.seed(100)
from sklearn.model_selection import train_test_split
data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.20, random_state=100)
print(len(data_train),len(data_test),len(labels_train),len(labels_test))
print(labels_train.value_counts())
print(labels_test.value_counts())

# #### Checking the data is split in equal distribution or not
"""
train_0_dist = 711/1410
print(train_0_dist)
train_1_dist = 699/1410
print(train_1_dist)
test_0_dist = 306/605
print(test_0_dist)
test_1_dist = 299/605
print(test_1_dist)
"""

# ## Random Forest

from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(data_train,labels_train)
rf_pred_label = RFmodel.predict(data_test)
#print(list(labels_test)),print(list(rf_pred_label))

from sklearn.metrics import confusion_matrix,accuracy_score
cm2 = confusion_matrix(labels_test,rf_pred_label)
print(cm2)
print(accuracy_score(labels_test,rf_pred_label))
"""
# Saving the model to a file
import pickle
file_name = "RandomForestModel.sav"
pickle.dump(RFmodel,open(file_name,'wb'))
"""

