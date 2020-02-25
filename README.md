## Phishing-Website-Detection

Over the years there have been many attacks of Phishing and many people have lost huge sums of money by becoming a victim of phishing attack. In a phishing attack emails are sent to user claiming to be a legitimate organization, where in the email asks user to enter information like name, telephone, bank account number important passwords etc. such emails direct the user to a website where in user enters these personal information. These websites also known as phishing website now steal the entered user information and carries out
illegal transactions thus causing harm to the user.Phishing website and their mails are sent to millions of users daily and thus are still a big concern for cyber security.


### Overview of the project

Phishing is one of the luring techniques used by phishing artist in the intention of exploiting the personal details of unsuspected users. Phishing website is a mock website that looks similar in appearance but different in destination. The unsuspected users post their data thinking that these websites come from trusted financial institutions. Several antiphishing techniques emerge continuously but phishers come with new technique by breaking all the antiphishing mechanisms. Hence there is a need for efficient mechanism for the prediction of phishing website.

This project employs Machine-learning technique for modelling the prediction task and supervised learning algorithms namely Decision tree induction, Naïve bayes classification and Random Forest are used for exploring the results. 

**Steps typically involved in this project**
1. _Feature Extraction_
  
2. _Data Preprocessing_
    - Filtering the extracted features data.(Removing unnecessary columns for the training the model)

3. _Training the model_
   
   1. Training the model with Decision Tree C5.0 algorithm
     - Calculating the accuracy of the model
   2. Training the model with Random Forest model 
     - Calculating the accuracy of the model
  By evaluating the performance of the model, choosing the best fit for this problem
  
   **Any Classification Algorithm can be used such as SVM,KNN,Naive Bayes but we are testing only with Decision Tree C5.0 and Random     Forest because many citations on this project has stated that Random Forest is the best fit**

4. _Evaluating the model and Testing the model_
     - By providing input(url) either from desktop app or web-app,classifying whether it is legitimate or phishing
    




