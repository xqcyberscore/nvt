###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_credential_cmd_exec_vuln.nasl 3517 2016-06-14 12:46:45Z benallard $
#
# GNU Bash Environment Variable Handling Shell RCE Vulnerability (LSC)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804490");
  script_version("$Revision: 3517 $");
  script_cve_id("CVE-2014-6271");
  script_bugtraq_id(70103);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 14:46:45 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-09-26 13:50:37 +0530 (Fri, 26 Sep 2014)");

  script_name("GNU Bash Environment Variable Handling Shell RCE Vulnerability (LSC)");

  script_tag(name: "summary" , value:"This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Login to the target machine with ssh
  credentials and check its possible to execute the commands via GNU bash shell.");

  script_tag(name: "insight" , value:"GNU bash contains a flaw that is triggered
  when evaluating environment variables passed from another environment.
  After processing a function definition, bash continues to process trailing
  strings.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  or local attackers to inject  shell commmands, allowing local privilege
  escalation or remote command execution depending on the application vector.

  Impact Level: Application");

  script_tag(name: "affected" , value:"GNU Bash through 4.3");

  script_tag(name: "solution" , value:"Apply the patch or upgrade to latest version,
  For updates refer to http://www.gnu.org/software/bash/");

  script_xref(name : "URL" , value : "https://access.redhat.com/solutions/1207723");
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=1141597");
  script_xref(name : "URL" , value : "https://blogs.akamai.com/2014/09/environment-bashing.html");
  script_xref(name : "URL" , value : "https://community.qualys.com/blogs/securitylabs/2014/09/24/");
  script_summary("Check for RCE vulnerability in GNU Bash");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/force/pty");
  exit(0);
}


include("ssh_func.inc");

if( get_kb_item( "ssh/force/pty" ) ) exit( 0 );

## Variable Initialization
sock = "";
cmd ="";
result = "";

## Confirm Linux, as SSH can be installed on Windows as well
result = get_kb_item("ssh/login/uname");
if("Linux" >!< result){
  exit(0);
}

## Checking OS
sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

if( ! get_kb_item( "shellshock/bash/installed" ) )
{
  cmd = "bash --version";
  result = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE);
  if( "GNU bash" >!< result ) exit( 0 );
  replace_kb_item( name:"shellshock/bash/installed", value:TRUE );
}

cmd = 'env x="() { :;}; echo vulnerable" bash -c "echo this is a test"';
result = ssh_cmd(socket:sock, cmd:cmd);

close(sock);

## check the result
if("vulnerable" >< result)
{
  security_message(0);
  exit(0);
}
