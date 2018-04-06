###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sun_java_ws_code_exec_vuln_lin.nasl 9349 2018-04-06 07:02:25Z cfischer $
#
# Sun Java Web Start Remote Command Execution Vulnerability (Linux)
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

tag_impact = "Successful exploitation allows remote code execution on the
  client machines.
  Impact Level: Application";
tag_affected = "Sun J2SE 6.0 Update 10 and earlier.";
tag_insight = "The flaw exists due to weakness in the BasicService showDocument method
  which does not validate the inputs appropriately. This can be exploited
  using a specially crafted Java Web Start application via file:\\ URL
  argument to the showDocument method.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.
For updates refer to http://java.sun.com/javase/downloads/index.jsp";
tag_summary = "This host is running Sun Java Web Start and is prone to Remote
  Command Execution Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800127");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-11-05 13:21:04 +0100 (Wed, 05 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4910");
  script_bugtraq_id(31916);
  script_name("Sun Java Web Start Remote Command Execution Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46119");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2008-10/0192.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("ssh_authorization.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

jwsVer = get_bin_version(full_prog_name:"javaws", version_argv:"-version",
                         ver_pattern:"Java.* Web Start ([0-9._]+)", sock:sock);
jwsVer = ereg_replace(pattern:"_", string:jwsVer[1], replace: ".");

if(jwsVer)
{
  if(version_is_less_equal(version:jwsVer, test_version:"1.6.0.10")){
    security_message(0);
  }
}
ssh_close_connection();
