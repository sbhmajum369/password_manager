# Password Manager (local)  

This app is for local password storage for anyone interested in a personalized secure password manager.  

It has strong encryption, brute force prevention and DDoS prevention.  

I am also open for collaboration to improve **cybersecurity** part and updating to a more useful look.  

> *At the moment the code is encrypted to avoid crawl BOTs*  



Follow the simple steps below to *RUN*.  

## Usage  

First install Python. Compatible versions are 3.10 to 3.12.  

1) Setup virtual environment (`py -_version_ venv _venv-name_`) and activate it (check windows vs linux activations).  
2) From inside the `venv`, install dependencies: `pip install -r requirements.txt`  
3) `cd prod`  
4) Start the app: `streamlit run app.py`  



## Fixing `st.cache` warning  

Go to `streamlit_cookies_manager.EncryptedCookieManager` library function and replace `st.cache` with `st.cache_data`.  


### To-Do  

1) update the `secrets.toml` password generation process.  
2) Make a Streamlit deployable executable.  

__________ 

Any comments and feedback will be appreciated. Please feel free to reach out at [LinkedIn](https://www.linkedin.com/in/subh-majum/)  

