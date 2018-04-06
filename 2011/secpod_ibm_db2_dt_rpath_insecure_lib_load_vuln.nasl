###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_dt_rpath_insecure_lib_load_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM DB2 'DT_RPATH' Insecure Library Loading Code Execution Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation allows local unauthenticated users to
gain elevated privileges and execute arbitrary code with root privileges.

Impact Level: Application.";

tag_affected = "IBM DB2 version 9.7";

tag_insight = "The flaws are due to an error in 'db2rspgn' and 'kbbacf1', which
allow users to gain privileges via a Trojan horse libkbb.so in the current
working directory.";

tag_solution = "Upgrade to version 9.7 Fix Pack 6, 10.1 Fix Pack 1, or higher,
http://www-01.ibm.com/support/docview.wss?rs=71&uid=swg27007053";

tag_summary = "The host is running IBM DB2 and is prone to insecure library
loading vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902489");
  script_version("$Revision: 9351 $");
  script_bugtraq_id(48514);
  script_cve_id("CVE-2011-4061");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-08 15:07:48 +0530 (Tue, 08 Nov 2011)");
  script_name("IBM DB2 'DT_RPATH' Insecure Library Loading Code Execution Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/518659");
  script_xref(name : "URL" , value : "http://www.nth-dimension.org.uk/downloads.php?id=77");
  script_xref(name : "URL" , value : "http://www.nth-dimension.org.uk/downloads.php?id=83");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Databases");
  script_dependencies("gb_ibm_db2_remote_detect.nasl");
  script_mandatory_keys("IBM-DB2/Remote/ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

ibmVer = get_kb_item("IBM-DB2/Remote/ver");
if(!ibmVer){
  exit(0);
}

if(ibmVer =~ "^0907\.*")
{
  # IBM DB2 9.7 => 09000
  if(version_is_equal(version:ibmVer, test_version:"09000"))
  {
    security_message(0);
    exit(0);
  }
}
