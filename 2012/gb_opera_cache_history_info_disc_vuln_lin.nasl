###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_cache_history_info_disc_vuln_lin.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Opera Cache History Information Disclosure Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
information about visited web page.

Impact Level: Application";

tag_affected = "Opera version 11.60 and prior on Linux";

tag_insight = "The flaw is due to an improper capturing of data about the times
of same origin policy violations during IFRAME and image loading attempts,
allows attacker to enumerate visited sites via crafted JavaScript code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is installed with Opera and is prone to information
disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802832");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2011-4690");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-04-09 16:39:39 +0530 (Mon, 09 Apr 2012)");
  script_name("Opera Cache History Information Disclosure Vulnerability (Linux)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47128");
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cachetime/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_linux_900037.nasl");
  script_require_keys("Opera/Linux/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"executable_version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
operaVer = NULL;

## Get the version
operaVer = get_kb_item("Opera/Linux/Version");
if(!operaVer){
  exit(0);
}

# Check for opera version is less than or equal to 11.60
if(version_is_less_equal(version:operaVer, test_version:"11.60")){
  security_message(0);
}
