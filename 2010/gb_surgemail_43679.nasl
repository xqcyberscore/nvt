###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_surgemail_43679.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# SurgeMail SurgeWeb Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "SurgeMail is prone to a cross-site scripting vulnerability because it
fails to sufficiently sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This can allow the attacker to steal cookie-based authentication
credentials and launch other attacks.

The issue affects version 4.3e; other versions may also be affected.";

tag_solution = "Reportedly the vendor fixed the issue in version 4.3g. Please contact
the vendor for more information.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100842");
  script_version("$Revision: 8495 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-05 12:35:02 +0200 (Tue, 05 Oct 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-3201");
  script_bugtraq_id(43679);
  script_name("SurgeMail SurgeWeb Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/43679");
  script_xref(name : "URL" , value : "http://ictsec.se/?p=108");
  script_xref(name : "URL" , value : "http://www.netwinsite.com/surgemail/");
  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_surgemail_detect.nasl");
  script_mandatory_keys("SurgeMail/Ver");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);

 exit(0);
}

include("http_func.inc");
include("version_func.inc");

surgemailVer = get_kb_item("SurgeMail/Ver");

if(!isnull(surgemailVer))
{
  if(version_is_equal(version:surgemailVer, test_version:"4.3e")){
    security_message(port:0);
    exit(0);
  }
}

exit(0);

