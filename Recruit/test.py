import google.generativeai as genai

genai.configure(api_key="AIzaSyDpTo3DWAgrLh-ZLYhaZYY6EFwvLjWTIlk")

for m in genai.list_models():
    print(m.name, m.supported_generation_methods)
