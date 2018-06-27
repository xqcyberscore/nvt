###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dovecot_consolidation.nasl 10329 2018-06-26 12:53:07Z jschulte $
#
# Dovecot Detection (Consolidation)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113212");
  script_version("$Revision: 10329 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-26 14:53:07 +0200 (Tue, 26 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-26 11:11:11 +0200 (Tue, 26 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  # Vulnerable version checks will have to be unreliable, as backports exist:
  # https://packages.debian.org/search?searchon=sourcenames&keywords=dovecot
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dovecot Detection (Consolidation)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("sw_dovecot_detect.nasl", "secpod_dovecot_detect.nasl");
  script_mandatory_keys("dovecot/detected");

  script_tag(name:"summary", value:"Reports Dovecot installation including version and location.");

  script_xref(name:"URL", value:"https://www.dovecot.org/");

  exit( 0 );
}

include( "host_details.inc" );
include( "cpe.inc" );

CPE = "cpe:/a:dovecot:dovecot:";
detected_version = "unknown";

if( version = get_kb_item( "dovecot/ssh/version" ) && version != "unknown" ) {
  detected_version = version;
}

concluded_protocols = "";
extra = 'Concluded via:\r\n\r\n';
foreach source ( make_list( "imap", "pop3", "ssh" ) ) {
  if( ( location = get_kb_item( "dovecot/" + source + "/location" ) )
    && ( concluded = get_kb_item( "dovecot/" + source + "/concluded" ) ) ) {
    extra += source + ' from "' + concluded + '" at "' + location + '"\r\n\r\n';

    if( concluded_protocols == "" )
      concluded_protocols = source;
    else
      concluded_protocols += ', ' + source;
  }
}

register_and_report_cpe( app: "Dovecot",
                         ver: detected_version,
                         concluded: concluded_protocols,
                         base: CPE,
                         expr: '^([0-9.]+)',
                         extra: extra );

exit( 0 );
