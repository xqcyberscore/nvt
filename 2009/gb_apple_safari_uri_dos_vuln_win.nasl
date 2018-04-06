###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_uri_dos_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apple Safari URI NULL Pointer Dereference DoS Vulnerability (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to cause browser crash.
  Impact Level: Application";
tag_affected = "Apple Safari version 4 beta and prior on Windows.";
tag_insight = "Browser fails to adequately sanitize user supplied input in URI feeds.
  Hence when certain characters are passed at the beginning of the URI,
  the NULL Pointer Dereference bug occurs, using '%', '{', '}', '`', '^', pipe
  and '&' characters.";
tag_solution = "No solution or patch was made available for at least one year since
  disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one..";
tag_summary = "This host is running Apple Safari web browser and is prone
  to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800524");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-03-05 06:25:55 +0100 (Thu, 05 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-0744");
  script_bugtraq_id(33909);
  script_name("Apple Safari URI NULL Pointer Dereference DoS Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/48943");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501229/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("version_func.inc");

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

# Apple Safari Version <= (4.28.16.0) 4 build 528.16
if(version_is_less_equal(version:safariVer, test_version:"4.28.16.0")){
  security_message(0);
}
