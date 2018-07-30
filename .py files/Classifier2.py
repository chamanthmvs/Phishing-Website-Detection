
# coding: utf-8

# In[1]:


import pandas as pd


# ## Collection of Data

# In[2]:


legitimate_urls = pd.read_csv("legitimate-urls.csv")
phishing_urls = pd.read_csv("phishing-urls.csv")


# In[3]:


legitimate_urls.head(10)
phishing_urls.head(10)


# ## Data PreProcessing
# #### Data is in two data frames so we merge them to make one dataframe
# Note: two dataframes has same column names

# In[4]:


urls = legitimate_urls.append(phishing_urls)


# In[5]:


urls.head(5)


# In[6]:


urls.columns


# #### Removing Unnecessary columns

# In[7]:


urls = urls.drop(urls.columns[[0,3,5]],axis=1)


# #### Since we merged two dataframes top 1000 rows will have legitimate urls and bottom 1000 rows will have phishing urls. So if we split the data now and create a model for it will overfit or underfit so we need to shuffle the rows before splitting the data into training set and test set

# In[8]:


# shuffling the rows in the dataset so that when splitting the train and test set are equally distributed
urls = urls.sample(frac=1).reset_index(drop=True)


# #### Removing class variable from the dataset

# In[9]:


urls_without_labels = urls.drop('label',axis=1)
urls_without_labels.columns
labels = urls['label']
#labels


# #### splitting the data into train data and test data

# In[49]:


from sklearn.model_selection import train_test_split
data_train, data_test, labels_train, labels_test = train_test_split(urls_without_labels, labels, test_size=0.30, random_state=100)


# In[37]:


print(len(data_train),len(data_test),len(labels_train),len(labels_test))


# In[151]:


print(labels_train.value_counts())
print(labels_test.value_counts())


# #### Checking the data is split in equal distribution or not

# In[158]:


train_0_dist = 711/1410
print(train_0_dist)
train_1_dist = 699/1410
print(train_1_dist)
test_0_dist = 306/605
print(test_0_dist)
test_1_dist = 299/605
print(test_1_dist)


# #### creating the model and fitting the data into the model

# In[50]:


from sklearn.tree import DecisionTreeClassifier
DTmodel = DecisionTreeClassifier(random_state=0)
DTmodel.fit(data_train,labels_train)


# #### predicting the result for test data

# In[51]:


pred_label = model.predict(data_test)


# In[52]:


print(pred_label),print(list(labels_test))


# #### creating confusion matrix and checking the accuracy

# In[54]:


from sklearn.metrics import confusion_matrix,accuracy_score
cm = confusion_matrix(labels_test,pred_label)
print(cm)
accuracy_score(labels_test,pred_label)


# ## Random Forest

# In[55]:


from sklearn.ensemble import RandomForestClassifier
RFmodel = RandomForestClassifier()
RFmodel.fit(data_train,labels_train)


# In[56]:


rf_pred_label = rfModel.predict(data_test)


# In[57]:


print(list(labels_test)),print(list(rf_pred_label))


# In[58]:


cm2 = confusion_matrix(labels_test,rf_pred_label)
cm2


# In[60]:


accuracy_score(labels_test,rf_pred_label)


# ### Improving the efficiency 

# In[138]:


imp_rf_model = RandomForestClassifier(n_estimators=100,max_depth=30,max_leaf_nodes=10000)


# In[140]:


imp_rf_model.fit(data_train,labels_train)


# In[142]:


imp_pred_label = imp_rf_model.predict(data_test)


# In[144]:


cm3 = confusion_matrix(labels_test,imp_pred_label)
cm3


# In[146]:


accuracy_score(labels_test,imp_pred_label)

