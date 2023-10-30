"""
    Module is responsible for declaring FastAPI endpoints.
"""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates


app = FastAPI()

templates = Jinja2Templates(directory="templates")


@app.get("/items/", response_class=HTMLResponse)
async def read_items(request: Request) -> HTMLResponse:
    context = {"request": request}
    return templates.TemplateResponse(name="items.html", context=context)
