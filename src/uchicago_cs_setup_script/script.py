# -*- coding: utf-8 -*-
#  Copyright (c) 2015, The University of Chicago
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#
#  - Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
#  - Neither the name of The University of Chicago nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.

import os
import click
import getpass
import sys
import yaml
import requests
from gitlab import Gitlab
from gitlab.exceptions import HttpError
import stat
import git
import time
import subprocess
from requests.exceptions import RequestException
from uchicago_cs_setup_script import RELEASE

SYSTEM_CONFIG_DIR = "/etc/cs-setup/conf.d"
FILENAME_TEMPLATE = "{}.yml"
GITHUB_CONFIG_URL = "https://raw.githubusercontent.com/uchicago-cs/setup-script/master/config/{}.yml"

VERBOSE = False

CONFIG_FIELDS = ["course-id",
                 "course-name",
                 "quarter",
                 "year",
                 "gitlab-hostname",
                 "gitlab-ssl",
                 "gitlab-group",
                 "gitlab-upstream-repo",
                 "chisubmit-init",
                 "chisubmit-course",
                 "bashrc-lines"]

SSH_DIR = os.path.expanduser("~/.ssh")
SSH_PRV_KEY = SSH_DIR + "/id_rsa"
SSH_PUB_KEY = SSH_DIR + "/id_rsa.pub"
BASH_RC = os.path.expanduser("~/.bashrc")

def get_default_repo_path(course_id, reponame):
    return os.path.expanduser("~/%s-%s" % (course_id, reponame))

def error(msg):
    print(msg)
    sys.exit(1)
    
def log(msg):
    if VERBOSE:
        print("LOG: " + msg)    

def load_config_file(file_or_string, source):
    config = yaml.load(file_or_string)
    if not isinstance(config, dict):
        error("File {} is not a valid configuration file".format(source))
    else:
        keys = config.keys()
        for k in keys:
            if k not in CONFIG_FIELDS:
                error("File {} contains an invalid field: {}".format(source, k))
    return config

def load_configuration(course_id, path = None):
    '''
    Load configuration for a given course. First, try the system-wide
    directory, then the local path (by default, the current directory),
    and then try to fetch the configuration from the GitHub repo.
    '''
    
    config = None
    
    if path is None:
        path = os.getcwd()
    
    files = [(SYSTEM_CONFIG_DIR + "/" + FILENAME_TEMPLATE).format(course_id), (path + "/" + FILENAME_TEMPLATE).format(course_id)]
    for fname in files:
        if os.path.exists(fname):
            with open(fname) as f:
                config = load_config_file(f, fname)

    if config is None:
        try:
            url = GITHUB_CONFIG_URL.format(course_id)
            r = requests.get(url)
        except ConnectionError as ce:
            error("Could not connect to {}: {}".format(url, ce))
        except RequestException as re:
            error_msg  = "Unexpected error when fetching configuration file: {}\n".format(re)
            error_msg += "URL: {}".format(url)
            error(error_msg)
        
        if r.status_code == 200:
            config = load_config_file(r.text, url)
        elif r.status_code == 404:
            log("Not found: {}".format(url))
            config = None
        else:
            error_msg  = "Unexpected error when fetching configuration file: {}\n"
            error_msg += "URL: {}\n".format(url)
            error_msg += "Status code: {}\n".format(r.status_code)
            error_msg += "Reason: {}\n".format(r.reason)
            error(error_msg)
            
    if config is None:
        error("Could not find configuration for course '{}'".format(course_id))
    else:
        return config
        
        
def connect_to_gitlab(gitlab_hostname, username, password, gitlab_ssl = True, verify_ssl = True):
    log("Connecting to GitLab")
    
    if not gitlab_ssl:
        hostname = "http://{}".format(gitlab_hostname)
    else:
        hostname = "https://{}".format(gitlab_hostname)

    try:
            g = Gitlab(hostname, verify_ssl = verify_ssl)
            rv = g.login(username, password)
            if not rv:
                error("Could not connect to Git server ({}). Reason unknown.".format(gitlab_hostname))
            else:
                return g
    except requests.exceptions.SSLError:
        error_msg  = "Your computer is not set up to trust the CS department's SSL certificate.\n"
        error_msg += "Try running the setup script with the --skip-ssl-verify option."
        error(error_msg)
    except HttpError as he:
        if str(he) == "401 Unauthorized":
            error("Could not connect to Git server (incorrect username/password)")
        else:
            error("Unexpected error while connecting to Git server (Reason: {})".format(he))


def get_gitlab_repo_data(gitlab, gitlab_group_name, gitlab_upstream_repo_name, repo):
    upstream_path = "{}/{}".format(gitlab_group_name, gitlab_upstream_repo_name)
    try:
        gitlab_upstream_repo = gitlab.getproject(upstream_path)
        if gitlab_upstream_repo == False:
            error("The upstream repository '{}' does not exist in the Git server".format(upstream_path))
    except HttpError as he:
        error("Unexpected error while accessing the upstream repository on the Git server (Reason: {})".format(he))
    
    gitlab_projects = {}
    try:
        page = 1
        done = False
        while not done:
            ps = gitlab.getprojects(page=page, per_page=100)
            if ps == False:
                error("Unexpected error while accessing the repositories on the Git server. Unknown reason.")
                        
            for p in ps:
                if p["namespace"]["path"] == gitlab_group_name and p["path"] != gitlab_upstream_repo_name:
                    gitlab_projects[p["path"]] = p
            
            if len(ps) < 100:
                done = True
            else:
                page += 1
    except HttpError as he:
        error("Unexpected error while accessing the repositories on the Git server (Reason: {})".format(he))
           
    if repo is not None:
        if not repo in gitlab_projects:
            error("Could not access repository '{}'. It either doesn't exist or you do not have access to it.".format(repo))
        else:
            gitlab_project = gitlab_projects[repo]
    else:
        if len(gitlab_projects) == 0:
            print()
            error("It seems like you do not have access to any Git repositories. Please check with your instructor.")
        
        gitlab_project_names = sorted(gitlab_projects.keys())
        
        print()
        print("You are a member of the following repositories.")
        print("Please select the one you want to use:")
        print()
        n = 1
        for repo_name in gitlab_project_names:
            print("[{}] {}".format(n, repo_name))
            n+=1
        print()
        print("[X] Exit")
        print()
        valid_options = [str(x) for x in range(1, len(gitlab_project_names)+1)] + ['X', 'x']
        option = None
        while option not in valid_options:
            option = input("Choose one: ")
            if option not in valid_options:
                print("'{}' is not a valid option!".format(option))
                print()
        
        if option in ['X', 'x']:
            exit(1)
        else:
            gitlab_project = gitlab_projects[gitlab_project_names[int(option)-1]]
            
            
    return gitlab_upstream_repo, gitlab_project


def generate_ssh_keys(username):
    assert not os.path.exists(SSH_PRV_KEY) and not os.path.exists(SSH_PUB_KEY)

    label = username + "@uchicago.edu"

    ssh_keygen_cmd = "ssh-keygen -t rsa -C \"{}\" -f ~/.ssh/id_rsa".format(label)

    try:
        from Crypto import version_info
        from Crypto.PublicKey import RSA
    except ImportError:
        error_msg  = "Your computer does not have the 'pycrypto' library necessary to\n"
        error_msg += "run this script. Try generating your SSH keys manually by running this:\n\n"
        error_msg += "    {}\n\n".format(ssh_keygen_cmd)
        error(error_msg)

    if version_info[0] < 2 or (version_info[0] == 2 and version_info[1] < 6):
        error_msg  = "Your computer has an old version of the 'pycrypto' library necessary to\n"
        error_msg += "run this script (version 2.6 or higher is required). Try generating your\n"
        error_msg += "SSH keys manually by running this:\n\n"
        error_msg += "    {}\n\n".format(ssh_keygen_cmd)
        error(error_msg)

    new_key = RSA.generate(2048)
    public_key = new_key.publickey().exportKey("OpenSSH")
    private_key = new_key.exportKey("PEM")

    if not os.path.exists(SSH_DIR):
        try:
            os.makedirs(SSH_DIR)
        except os.error as ose:
            error_msg  = "Could not create your SSH directory ({})\n".format(SSH_DIR)
            error_msg += "Reason: {}".format(ose)
            error(error_msg)
    elif not os.path.isdir(SSH_DIR):
            error("ERROR: {} is not a directory".format(SSH_DIR))

    try:
        f = open(SSH_PRV_KEY, "wb")
        f.write(private_key)
        f.close()
        os.chmod(SSH_PRV_KEY, 0 | stat.S_IRUSR)

        f = open(SSH_PUB_KEY, "wb")
        f.write(public_key)
        f.write(bytes(' ', encoding="UTF-8"))
        f.write(bytes(label, encoding="UTF-8"))
        f.close()
    except IOError as ioe:
        error("Error saving your SSH keys: {}".format(ioe))


def add_ssh_key_to_gitlab(gitlab, ssh_pubkey):
    
    key_to_add = ssh_pubkey.split()[1]

    try:
        ssh_keys = gitlab.getsshkeys()
    except HttpError as he:
        error("Unexpected error when accessing SSH keys on Git server (Reason: {})".format(he))    
    
    titles = set()
    for ssh_key in ssh_keys:
        titles.add(ssh_key["title"])
        if key_to_add == ssh_key["key"].split()[1]:
            log("User's SSH key is already in GitLab. Not adding it again.")
            return

    key_title_prefix = "Added by CS Setup Script"
    key_index = 1

    key_title = key_title_prefix
    while key_title in titles:
        key_index += 1
        key_title = "%s (%i)" % (key_title_prefix, key_index)

    try:
        rv = gitlab.addsshkey(key_title, ssh_pubkey)
        if not rv:
            error("Unexpected error when adding your SSH key to Git server. Reason unknown")
        log("Added key '{}': {}".format(key_title, ssh_pubkey))
    except HttpError as he:
        error("Unexpected error when adding your SSH key to Git server (Reason: {})".format(he))
    

def get_local_repo_path(course_id, repo_name, local_repo_path):
    if local_repo_path is not None:
        repo_path = local_repo_path
    else:
        repo_path = get_default_repo_path(course_id, repo_name)

    if os.path.exists(repo_path):
        try:
            git.Repo(repo_path)
            print("A valid repository already exists in {}".format(repo_path))
            exit(0)
        except git.exc.InvalidGitRepositoryError:
            error("ERROR: Directory {} already exists but it is not a Git repository".format(repo_path))
    else:
        try:
            os.makedirs(repo_path)
        except os.error as ose:
            error_msg  = "Could not create directory {}\n".format(repo_path)
            error_msg += "Reason: {}".format(ose)
            error(error_msg)
            
    return repo_path

def print_git_error(gce):
    print("\nGit command: " + " ".join(gce.command))
    print("\nGit error message")
    print("-----------------")
    print(gce.stderr)

def create_local_repo(repo_path, repo_url, upstream_repo_url, name, email, skip_push):
    try:
        repo = git.Repo.clone_from(repo_url, repo_path)
    except git.exc.GitCommandError as gce:
        print("ERROR: Could not clone from remote repository {} into {}".format(repo_url, repo_path))
        print_git_error(gce)
        exit(1)

    cr_global = repo.config_reader(config_level="global")    
    cw_global = repo.config_writer(config_level="global")
    cw =  repo.config_writer()
    
    if not cr_global.has_section("user"):
        cw_global.set_value("user", "name", name)
        cw_global.set_value("user", "email", email)
    else:
        cw.set_value("user", "name", name)
        cw.set_value("user", "email", email)        
            
    if not cr_global.has_option("push", "default"):
        cw_global.set_value("push", "default", "simple")
          
    cw.release()
    cw_global.release()  
    
    origin = repo.remotes[0]

    try:
        upstream = repo.create_remote("upstream", upstream_repo_url)
    except git.exc.GitCommandError as gce:
        print("ERROR: Could not add upstream repository {}".format(upstream_repo_url))
        print_git_error(gce)
        exit(1)

    try:
        upstream.pull("master")
    except git.exc.GitCommandError as gce:
        print("ERROR: Could not pull from upstream repository") 
        print_git_error(gce)
        exit(1)
  
    try:
        if not skip_push:
            origin.push("master", u=True)
    except git.exc.GitCommandError as gce:
        print("ERROR: Could not pull from upstream repository") 
        print_git_error(gce)
        exit(1)
        

def construct_chisubmit_command(repo_path, username, password, chisubmit_course):
    return ["chisubmit", "--work-dir", repo_path,
                                           "--config-dir", repo_path + "/.chisubmit",
                                           "init",
                                           "--username", username,
                                           "--password", password,
                                           # TODO: Use Git credentials obtained earlier
                                           "--git-username", username,
                                           "--git-password", password,
                                           chisubmit_course
                                           ]
        
        
def cmd_error(cmd, p, rc = None):
    print("ERROR while running this command:\n\n{}\n\n".format(" ".join(cmd)))
    if rc is None:
        print("Command timed out before returning.")
    else:
        print("Return code: {}".format(rc))
    print("\nStandard Output")
    print("---------------")
    print(p.stdout.read().decode("utf-8") )
    print("\nStandard Error")
    print("---------------")
    print(p.stderr.read().decode("utf-8") )
    sys.exit(1)
        
        
def add_bash_rc(config, repo_path):
    BASH_RC = os.path.expanduser("~/.bashrc")

    if not "bashrc-lines" in config:
        return

    lines_to_add = config["bashrc-lines"]
    lines_to_add = [l.format(repo_path=repo_path, **config) for l in lines_to_add]

    if os.path.exists(BASH_RC):
        bashrcf = open(BASH_RC)
        lines = bashrcf.readlines()
        bashrcf.close()

        # If the lines we're looking for exist, they're likely at the
        # end of the file, so let's search from the end.
        lines.reverse()
        
        actually_add = []

        for line_to_add in lines_to_add:
            found = False
            for line in lines:
                if line_to_add in line:
                    found = True
                    break
            if not found:
                actually_add.append(line_to_add)            

        if len(actually_add) > 0:
            bashrcf = open(BASH_RC, "a")
            bashrcf.write("\n")
            for line in actually_add:
                bashrcf.write(line + "\n")
            bashrcf.close()
    else:
        log("~/.bashrc does not exist. Creating one.")
        bashrcf = open(BASH_RC, "w")
        for line_to_add in lines_to_add:
            bashrcf.write(line_to_add + "\n")
        bashrcf.close()


@click.command(name="cs-setup-script")
@click.argument('course_id')
@click.option('--cnetid', type=str)
@click.option('--password', type=str)
@click.option('--config-dir', type=str)
@click.option('--repo', type=str)
@click.option('--local-repo-path', type=str)
@click.option('--skip-ssl-verify', is_flag=True)
@click.option('--skip-push', is_flag=True)
@click.option('--verbose', '-v', is_flag=True)
@click.version_option(version=RELEASE)
def cmd(course_id, cnetid, password, config_dir, repo, local_repo_path, skip_ssl_verify, skip_push, verbose):
    
    #
    # Load configuration
    #
    
    config = load_configuration(course_id)
    
    #
    # Get username and password
    #
    
    if cnetid is None:
        guess_user = getpass.getuser()
    else:
        guess_user = cnetid
    
    user_prompt = "Enter your CNetID [{}]: ".format(guess_user)
    password_prompt = "Enter your CNetID password: "
    
    if cnetid is None:
        username = input(user_prompt)
        if len(username.strip()) == 0:
            username = guess_user
    else:
        username = cnetid
        print(user_prompt + cnetid)
        
    if password is None:
        password = getpass.getpass(password_prompt)
    else:
        print(password_prompt)
    
    #
    # Setup variables
    #
    
    if verbose:
        global VERBOSE
        VERBOSE = True

    # This will only work on the CS machines, where the InCommon CA certificate
    # is included in the system CA bundle.
    # For other systems, the user should just use the --skip-ssl-verify option.
    ca_bundle = "/etc/ssl/certs/ca-certificates.crt"
    if skip_ssl_verify:
        verify_ssl = False
    elif os.path.exists(ca_bundle):
        verify_ssl = ca_bundle
    else:
        verify_ssl = True


    #
    # Connect to GitLab and get repository information
    #

    gitlab = connect_to_gitlab(gitlab_hostname = config["gitlab-hostname"], 
                               username = username, 
                               password = password, 
                               gitlab_ssl = config["gitlab-ssl"], 
                               verify_ssl = verify_ssl)

    gitlab_upstream_repo, gitlab_repo = get_gitlab_repo_data(gitlab, config["gitlab-group"], config["gitlab-upstream-repo"], repo)


    #
    # Setup SSH keys
    #
    
    if not os.path.exists(SSH_PRV_KEY) and not os.path.exists(SSH_PUB_KEY):
        generate_ssh_keys(username)

    try:
        f = open(SSH_PUB_KEY)
        ssh_pubkey = f.read().strip()
        f.close()
    except IOError as ioe:
        error("Error reading your SSH public key: {}".format(ioe))


    print("Setting up your Git repository...")
    add_ssh_key_to_gitlab(gitlab, ssh_pubkey)

    # We need to add an artificial delay because, apparently, the SSH key is
    # not immediately available on the GitLab server
    time.sleep(2)
    
    #
    # Create local repository
    #
    
    repo_path = get_local_repo_path(config["course-id"], gitlab_repo["name"], local_repo_path)

    gitlab_user = gitlab.currentuser()
    name = gitlab_user["name"]
    email = gitlab_user["email"]

    create_local_repo(repo_path, gitlab_repo["ssh_url_to_repo"], gitlab_upstream_repo["ssh_url_to_repo"], name, email, skip_push)      

    print("Your git repository has been created in %s" % repo_path)
    
    #
    # Run chisubmit init
    #
    if config.get("chisubmit-init", False):
        chisubmit_course = config["chisubmit-course"]
        
        print("")
        cmd = construct_chisubmit_command(repo_path, username, password, chisubmit_course)
        
        cmd_redacted = construct_chisubmit_command(repo_path, username, "...", chisubmit_course)
        
        try:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError:
            error("Could not run chisubmit.")
        
        print("Setting up chisubmit...")
        try:
            rc = p.wait(15)
        except subprocess.TimeoutExpired:
            cmd_error(cmd_redacted, p)
        
        if rc == 0:
            print("chisubmit has been set up. You can use chisubmit commands inside {}\n".format(repo_path))
        else:
            cmd_error(cmd_redacted, p, rc)
        
    add_bash_rc(config, repo_path)
    