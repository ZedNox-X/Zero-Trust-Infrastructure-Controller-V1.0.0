from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
class Settings(BaseSettings):
    app_name:str="zero-trust-controller"; environment:str="development"; database_url:str="sqlite:///./ztc.db"; api_token:str="dev-token"; policy_dir:str="policies"; fail_closed:bool=True
    model_config=SettingsConfigDict(env_file=".env",extra="ignore")
@lru_cache
def get_settings(): return Settings()
