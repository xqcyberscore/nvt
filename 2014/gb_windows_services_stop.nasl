###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_windows_services_stop.nasl 3400 2016-05-30 09:49:51Z antu123 $
#
# Windows Services Stop
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804787");
  script_version("$Revision: 3400 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-05-30 11:49:51 +0200 (Mon, 30 May 2016) $");
  script_tag(name:"creation_date", value:"2014-11-05 11:50:33 +0530 (Wed, 05 Nov 2014)");
  script_name("Windows Services Stop");

  script_tag(name: "summary" , value: "If the windows services started manually by nasl
  then stop those services before exit.");

  script_summary("Stop windows services");
  script_category(ACT_END);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows");
  script_mandatory_keys("RemoteRegistry/Win/Service/Manual/Start");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");

## Variable Initialization
cmd = "";
username = "";
password = "";
serQueryRes = "";
serQueryStat = "";

port = kb_smb_transport();
if(!port){
  port = 139;
}

if(!get_port_state(port)){
  exit(0);
}

if (!defined_func("win_cmd_exec")){
  exit(0);
}

username =  string(get_kb_item("SMB/login_filled/0"));
password = string(get_kb_item("SMB/password_filled/0"));
domain = string(get_kb_item("SMB/domain_filled/0"));
if (!username && !password) exit(0);

if(domain)
username = string(domain, "/", username);


function run_command(command)
{
  ## Run the Command and get the Response
  serQueryRes = win_cmd_exec(cmd:command, password:password, username:username);

  if("Access is denied" >< serQueryRes){
    error_message(data:"SC Command Error: Access is denied.");
  }

  else if("The specified service does not exist" >< serQueryRes){
    error_message(data:"SC Command Error: The specified service does not exist.");
  }

  else if("The service cannot be started" >< serQueryRes && "it is disabled" >< serQueryRes){
    error_message(data:"SC Command Error: Unable to start the service, May be it is Disabled.");
  }

  else if("OpenService FAILED" >< serQueryRes && "specified service does not exist" >< serQueryRes){
    error_message(data:"SC Command Error: The Specified Service does not Exit.");
  }

  else if("StartService FAILED" >< serQueryRes){
    error_message(data:"SC Command Error: Failed to start the service.");
  }

  else if("An instance of the service is already running" >< serQueryRes){
    error_message(data:"SC Command Error: An instance of the service is already running.");
  }

  else
  {
    ## Confirm the "sc query" Response
    if("SERVICE_NAME" >< serQueryRes && "STATE" >< serQueryRes &&
                            "SERVICE_EXIT_CODE" >< serQueryRes)
    {
      ## Get the state of the service
      serStat = eregmatch(pattern:"STATE.*: [0-9]  ([a-zA-Z_]+)", string:serQueryRes);
      return serStat[1];
    }
  }
}


service_kb_list = get_kb_list("*/Win/Service/Manual/Start");
if(!service_kb_list) exit(0);

foreach service_kb (keys(service_kb_list))
{
  service = split(service_kb, sep:"/", keep:FALSE);

  if(service[0])
  {
    ## To get the status of the service
    cmd = "cmd /c sc query " + service[0];
    serQueryStat = run_command(command:cmd);

    ## Check wheather it is in running state
    if("RUNNING" >< serQueryStat)
    {
      ## To stop the service
      cmd = "cmd /c sc stop " + service[0];
      serQueryStat = run_command(command:cmd);

      ## Confirm wheather it is stopped or not
      if("STOP_PENDING" >< serQueryStat)
      {
        ## To get the status of the service
        cmd = "cmd /c sc query " + service[0];
        serQueryStat = run_command(command:cmd);

        if("STOPPED" >!< serQueryStat)
        {
          error_message(data:"SC Command Error: Failed to stop the service: " + service[0]);
        }
      }
    }
  }
}
