##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_virtualbox_acquiredaemonlock_vuln_lin_900408.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Sun xVM VirtualBox Insecure Temporary Files Vulnerability (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Successful exploitation will let the attacker perform malicious actions
  with the escalated previleges.
  Impact Level: Application";
tag_affected = "Sun xVM VirutalBox version prior to 2.0.6 versions on all Linux platforms.";
tag_insight = "Error is due to insecured handling of temporary files in the 'AcquireDaemonLock'
  function in ipcdUnix.cpp. This allows local users to overwrite arbitrary
  files via a symlink attack on a '/tmp/.vbox-$USER-ipc/lock' temporary file.";
tag_solution = "Upgrade to the latest version 2.0.6 or above.
  http://www.virtualbox.org/wiki/Downloads";
tag_summary = "This host is installed with Sun xVM VirtualBox and is prone to
  Insecure Temporary Files vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900408");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_bugtraq_id(32444);
  script_cve_id("CVE-2008-5256");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("General");
  script_name("Sun xVM VirtualBox Insecure Temporary Files Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/Advisories/32851");
  script_xref(name : "URL" , value : "http://www.virtualbox.org/wiki/Changelog");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");

sock = ssh_login_or_reuse_connection();
if(sock)
{
  xvm_linux = ssh_cmd(socket:sock, cmd:"VBoxDeleteIF -v", timeout:120);
  ssh_close_connection();
  if("VirtualBox" >< xvm_linux){
    pattern = "version ([0-1](\..*)?|2\.0(\.[0-5])?)$";
    if(egrep(pattern:pattern, string:xvm_linux)){
      security_message(0);
    }
  }
}
