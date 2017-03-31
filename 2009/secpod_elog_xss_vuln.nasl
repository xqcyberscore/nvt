###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_elog_xss_vuln.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# ELOG Logbook Cross Site Scripting Vulnerability
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

tag_impact = "Attackers can exploit this issue to steal cookie-based authentication
  credentials by conducting Cross-Site Scripting attacks on the affected
  system.
  Impact Level: System/Application";
tag_affected = "ELOG versions prior to 2.7.2";
tag_insight = "An error occurs while processing malicious user supplied data passed into
  the 'logbook' module and can be exploited to inject arbitrary HTML and
  script code in the context of the affected application.";
tag_solution = "Upgrade ELOG Version to 2.7.2 or later.
  https://midas.psi.ch/elog/download/";
tag_summary = "This host has ELOG installed and is prone to cross-site
  scripting vulnerability.";

if(description)
{
  script_id(900939);
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-7206");
  script_bugtraq_id(27526);
  script_name("ELOG Logbook Cross Site Scripting Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_elog_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/40124");
  script_xref(name : "URL" , value : "https://midas.psi.ch/elog/download/ChangeLog");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

elogPort = get_http_port(default:8080);

if(!elogPort)
{
  exit(0);
}
elogVer = get_kb_item("www/" + elogPort + "/ELOG");

if(elogVer != NULL)
{
  # Check for ELOG versions prior to 2.7.2 => 2.7.2-2012
  if(version_is_less(version:elogVer, test_version:"2.7.2.2012")){
    security_message(elogPort);
  }
}
