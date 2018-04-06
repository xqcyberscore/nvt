###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kvirc_arg_inj_vuln_win.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# KVIrc URI Handler Argument Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
commands.

Impact Level: Application";

tag_affected = "KVirc version 3.4.2 and prior on Windows";

tag_insight = "The flaw is due to an improper validation of user supplied
input, which can be exploited by persuading a victim to open a
specially-crafted 'irc:///', 'irc6:///', 'ircs:///', or 'ircs6:///' URI.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host has KVIrc installed and is prone to Argument Injection
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901011");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-09-02 09:58:59 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-7070");
  script_bugtraq_id(32410);
  script_name("KVIrc URI Handler Argument Injection Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/7181");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/46779");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
  script_dependencies("secpod_kvirc_detect_win.nasl");
  script_require_keys("Kvirc/Win/Ver");
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

# Get for KVIrc Version
kvircVer = get_kb_item("Kvirc/Win/Ver");

if(kvircVer != NULL)
{
  # Check for KVirc version <= 3.4.2
  if(version_is_less_equal(version:kvircVer, test_version:"3.4.2")){
    security_message(0);
  }
}
