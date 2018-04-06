###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_edir_mult_vuln_nov08_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Novell eDirectory Multiple Vulnerabilities Nov08 - (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
###############################################################################

tag_impact = "Successful exploitation allows remote code execution on the target
  machines or can allow disclosure of potentially sensitive information or
  can cause denial of service condition.
  Impact Level: Application";
tag_affected = "Novell eDirectory 8.8 SP2 and prior on Linux.";
tag_insight = "The flaws are due to
  - boundary error in LDAP and NDS services.
  - boundary error in HTTP language header and HTTP content-length header.
  - HTTP protocol stack(HTTPSTK) that does not properly filter HTML code from
    user-supplied input.";
tag_solution = "Update to 8.8 Service Pack 3.
  http://support.novell.com/patches.html";
tag_summary = "This host is running Novell eDirectory and is prone to Multiple
  Vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800136");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-21 14:18:03 +0100 (Fri, 21 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5091", "CVE-2008-5092", "CVE-2008-5093", "CVE-2008-5094");
  script_bugtraq_id(30947);
  script_name("Novell eDirectory Multiple Vulnerabilities Nov08 - (Linux)");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020785.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020786.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020787.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020788.html");
  script_xref(name : "URL" , value : "http://www.novell.com/support/viewContent.do?externalId=3426981");
  script_xref(name : "URL" , value : "http://www.novell.com/documentation/edir873/sp10_readme/netware/readme.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  script_require_ports(8028, 8030);

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

port = 8028;
if(!get_port_state(port))
{
  port = 8030;
  if(!get_port_state(port)){
    exit(0);
  }
}

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

eDirVer = get_bin_version(full_prog_name:"ndsd", version_argv:"--version",
          ver_pattern:"Novell eDirectory ([0-9.]+ (SP[0-9]+)?)", sock:sock);
if(eDirVer != NULL)
{
  eDirVer = ereg_replace(pattern:" ", string: eDirVer[1], replace:".");
  if(version_is_less(version:eDirVer, test_version:"8.8.SP3")){
    security_message(port);
  }
}
ssh_close_connection();
