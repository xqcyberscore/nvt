##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rekonq_mult_xss_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# rekonq 'Error Page' Cross-Site Scripting Vulnerabilities.
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
################################i###############################################

tag_impact = "Successful exploitation will allow attackers to crash fresh
instance, inject the malicious content into error message, access the cookies
when the hostname under which the cookies have been set.

Impact Level: Application.";

tag_affected = "Rekonq version 0.5 and prior.";

tag_insight = "The multiple flaws are due to:
- An error in the handling of a URL associated with a nonexistent domain name
  which is related to 'webpage.cpp',
- An error in hanlding of unspecified vectors related to 'webview.cpp'
- An error in the handing of 'about:' views for favorites, bookmarks, closed
  tabs, and history.";

tag_solution = "Upgrade to version 0.6 or later,
For updates refer to http://sourceforge.net/projects/rekonq/files";

tag_summary = "This host is installed with rekonq and is prone to cross-site
scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801422");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-10 14:39:31 +0200 (Tue, 10 Aug 2010)");
  script_cve_id("CVE-2010-2536");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("rekonq 'Error Page' Cross-Site Scripting Vulnerabilities");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_rekonq_detect.nasl");
  script_mandatory_keys("rekonq/Linux/Ver");

  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/40646");
  script_xref(name : "URL" , value : "https://bugs.kde.org/show_bug.cgi?id=217464");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&m=127971194610788&w=2");

  exit(0);
}


include("version_func.inc");

## Get the version from KB
rekonqVer = get_kb_item("rekonq/Linux/Ver");
if(!rekonqVer){
  exit(0);
}

## Check rekonq version <= 0.5
if(version_is_less_equal(version:rekonqVer, test_version:"0.5.0")){
  security_message(0);
}
