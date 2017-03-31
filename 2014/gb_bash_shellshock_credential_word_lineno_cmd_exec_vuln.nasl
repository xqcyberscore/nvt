###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bash_shellshock_credential_word_lineno_cmd_exec_vuln.nasl 3517 2016-06-14 12:46:45Z benallard $
#
# GNU Bash Off-by-one aka 'word_lineno' Buffer Overflow Vulnerability (LSC)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802084");
  script_version("$Revision: 3517 $");
  script_cve_id("CVE-2014-7187");
  script_bugtraq_id(70154);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-14 14:46:45 +0200 (Tue, 14 Jun 2016) $");
  script_tag(name:"creation_date", value:"2014-10-01 14:11:51 +0530 (Wed, 01 Oct 2014)");

  script_name("GNU Bash Off-by-one aka 'word_lineno' Buffer Overflow Vulnerability (LSC)");

  script_tag(name: "summary" , value:"This host is installed with GNU Bash Shell
  and is prone to command execution vulnerability.");

  script_tag(name: "vuldetect" , value:"Login to the target machine with ssh
  credentials and check its possible to execute the commands via GNU bash
  shell.");

  script_tag(name: "insight" , value:"GNU bash contains an off-by-one overflow
  condition that is triggered when handling deeply nested flow control
  constructs.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  attackers to execute arbitrary commands.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"GNU Bash through 4.3 bash43-026");

  script_tag(name: "solution" , value:"Apply the appropriate patch. For
  updates refer to refer to http://www.gnu.org/software/bash/");

  script_xref(name : "URL" , value : "https://shellshocker.net/");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2014/09/26/2");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2014/09/28/10");
  script_xref(name : "URL" , value : "https://access.redhat.com/security/cve/CVE-2014-7187");

  script_summary("Check for Off-by-one aka 'word_lineno' vulnerability in GNU Bash");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("General");
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

## Command be to be executed
cmd = '(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in ' +
      '{1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 ' +
      'vulnerable, word_lineno"';
result = ssh_cmd(socket:sock, cmd:cmd, nosh:TRUE);
close(sock);

## check the result
if("word_lineno vulnerable" >< result)
{
  security_message(0);
  exit(0);
}
