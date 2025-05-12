# src/sfss-cli.py

"""
CLI for Secure File Storage System operations: upload, download, list, delete.
"""
print("[DEBUG] sfss_cli.py loaded")

import click
from src.auth.github_oauth import github_login, logout as oauth_logout
from src.storage.file_manager import upload_file, download_file, list_files, delete_file
from src.utils.logger import log_event
from src.utils.session_handler import load_session
from src.utils.validators import is_valid_path as validate_file_path


print("[DEBUG] CLI loaded successfully.")

@click.group()
def cli():
    """Secure File Storage System CLI"""
    pass


@cli.command(help="Login to GitHub using OAuth.")
def login():
    log_event("INFO", "Initiating GitHub OAuth login...")
    github_login()


@cli.command(help="Logout and clear the current session.")
def logout():
    log_event("INFO", "Logging out and clearing session.")
    oauth_logout()  # Proper call to the logout function from github_oauth


@cli.command(help="Check the current session status.")
def status():
    session = load_session()
    if session:
        click.secho(f"Logged in as: {session['username']} ({session['email']})", fg="green")
    else:
        click.secho("No active session found.", fg="red")


@cli.command(help="Upload and encrypt a file to secure storage.")
@click.argument("file_path")
def upload(file_path):
    session = load_session()
    if not session:
        click.secho("No active session found. Please log in.", fg="red")
        return

    log_event("INFO", f"Uploading file: {file_path}")
    response = upload_file(file_path)

    if "ERROR" in response:
        click.secho(response, fg="red")
    else:
        click.secho(response, fg="green")


@cli.command(help="Download and decrypt a file from secure storage.")
@click.argument("filename")
@click.argument("output_path")
def download(filename, output_path):
    session = load_session()
    if not session:
        click.secho("No active session found. Please log in.", fg="red")
        return

    log_event("INFO", f"Downloading file: {filename} to {output_path}")
    response = download_file(filename, output_path)

    if "ERROR" in response:
        click.secho(response, fg="red")
    else:
        click.secho(response, fg="green")


@cli.command(help="List all encrypted files in secure storage.")
def list():
    """Command is now 'list' instead of 'list_files'"""
    session = load_session()
    if not session:
        click.secho("No active session found. Please log in.", fg="red")
        return

    log_event("INFO", "Listing all encrypted files.")
    files = list_files()
    if files:
        click.secho("\n".join(files), fg="green")
    else:
        click.secho("No files found.", fg="yellow")


@cli.command(help="Delete a file from secure storage.")
@click.argument("filename")
def delete(filename):
    session = load_session()
    if not session:
        click.secho("No active session found. Please log in.", fg="red")
        return

    log_event("INFO", f"Deleting file: {filename}")
    response = delete_file(filename)

    if "ERROR" in response:
        click.secho(response, fg="red")
    else:
        click.secho(response, fg="green")


if __name__ == "__main__":
    cli()