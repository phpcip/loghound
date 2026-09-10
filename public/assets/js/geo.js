/*
 * Loghound — country centroids.
 *
 * Why this file exists: SPEC §4.1 defines `geo_p` as an indexed `location` field with no
 * docValues, which means Solr can search it but cannot facet on it or return it. The
 * Networks map is therefore built from `country_s` counts, and needs a coordinate per
 * country to plot them.
 *
 * Shipping this table (about 3 KB) rather than a world GeoJSON (several hundred) keeps
 * the panel air-gapped, keeps the CSP closed, and keeps the page fast. The trade is
 * resolution: the map is honest about being country-level and is labelled as such.
 *
 * Coordinates are approximate visual centroids — chosen so the dot lands on the country,
 * which for a few awkward shapes is not the mathematical centroid. They are for plotting,
 * not for navigation.
 *
 * Lookup accepts either an ISO 3166-1 alpha-2 code or an English country name, because
 * geolocation providers differ on which they return and the schema does not pin it down.
 */

'use strict';

/** ISO 3166-1 alpha-2 → [latitude, longitude, English name]. */
const CENTROIDS = {
    AE: [23.9, 54.3, 'United Arab Emirates'],
    AR: [-35.4, -65.2, 'Argentina'],
    AT: [47.6, 14.1, 'Austria'],
    AU: [-25.7, 134.5, 'Australia'],
    AZ: [40.3, 47.6, 'Azerbaijan'],
    BA: [44.2, 17.8, 'Bosnia and Herzegovina'],
    BD: [23.8, 90.2, 'Bangladesh'],
    BE: [50.6, 4.6, 'Belgium'],
    BG: [42.8, 25.2, 'Bulgaria'],
    BH: [26.0, 50.5, 'Bahrain'],
    BO: [-16.7, -64.7, 'Bolivia'],
    BR: [-10.8, -52.9, 'Brazil'],
    BY: [53.5, 28.0, 'Belarus'],
    CA: [58.0, -100.5, 'Canada'],
    CH: [46.8, 8.2, 'Switzerland'],
    CL: [-37.7, -71.4, 'Chile'],
    CM: [5.7, 12.7, 'Cameroon'],
    CN: [35.0, 104.2, 'China'],
    CO: [3.9, -73.1, 'Colombia'],
    CR: [9.9, -84.2, 'Costa Rica'],
    CY: [35.0, 33.2, 'Cyprus'],
    CZ: [49.7, 15.3, 'Czechia'],
    DE: [51.1, 10.4, 'Germany'],
    DK: [56.0, 10.0, 'Denmark'],
    DO: [18.9, -70.5, 'Dominican Republic'],
    DZ: [28.2, 2.6, 'Algeria'],
    EC: [-1.4, -78.4, 'Ecuador'],
    EE: [58.7, 25.5, 'Estonia'],
    EG: [26.5, 29.9, 'Egypt'],
    ES: [40.2, -3.6, 'Spain'],
    ET: [8.6, 39.6, 'Ethiopia'],
    FI: [64.5, 26.3, 'Finland'],
    FR: [46.6, 2.4, 'France'],
    GB: [54.1, -2.9, 'United Kingdom'],
    GE: [42.2, 43.5, 'Georgia'],
    GH: [7.9, -1.0, 'Ghana'],
    GR: [39.1, 22.4, 'Greece'],
    GT: [15.7, -90.4, 'Guatemala'],
    HK: [22.3, 114.2, 'Hong Kong'],
    HR: [45.1, 16.4, 'Croatia'],
    HU: [47.2, 19.4, 'Hungary'],
    ID: [-2.5, 118.0, 'Indonesia'],
    IE: [53.2, -8.1, 'Ireland'],
    IL: [31.4, 34.9, 'Israel'],
    IN: [22.9, 79.6, 'India'],
    IQ: [33.0, 43.7, 'Iraq'],
    IR: [32.6, 54.3, 'Iran'],
    IS: [64.9, -18.6, 'Iceland'],
    IT: [42.8, 12.6, 'Italy'],
    JO: [31.2, 36.8, 'Jordan'],
    JP: [36.5, 138.1, 'Japan'],
    KE: [0.5, 37.9, 'Kenya'],
    KG: [41.5, 74.6, 'Kyrgyzstan'],
    KH: [12.7, 104.9, 'Cambodia'],
    KR: [36.4, 127.8, 'South Korea'],
    KZ: [48.2, 67.3, 'Kazakhstan'],
    LB: [33.9, 35.9, 'Lebanon'],
    LK: [7.6, 80.7, 'Sri Lanka'],
    LT: [55.3, 23.9, 'Lithuania'],
    LU: [49.8, 6.1, 'Luxembourg'],
    LV: [56.9, 24.9, 'Latvia'],
    MA: [31.9, -7.1, 'Morocco'],
    MD: [47.2, 28.5, 'Moldova'],
    ME: [42.8, 19.3, 'Montenegro'],
    MK: [41.6, 21.7, 'North Macedonia'],
    MM: [21.2, 96.5, 'Myanmar'],
    MN: [46.9, 103.8, 'Mongolia'],
    MT: [35.9, 14.4, 'Malta'],
    MU: [-20.3, 57.6, 'Mauritius'],
    MX: [23.9, -102.5, 'Mexico'],
    MY: [4.1, 109.5, 'Malaysia'],
    NG: [9.6, 8.1, 'Nigeria'],
    NL: [52.2, 5.5, 'Netherlands'],
    NO: [64.6, 12.1, 'Norway'],
    NP: [28.3, 84.1, 'Nepal'],
    NZ: [-41.5, 172.8, 'New Zealand'],
    OM: [21.0, 57.0, 'Oman'],
    PA: [8.5, -80.1, 'Panama'],
    PE: [-9.2, -74.4, 'Peru'],
    PH: [12.1, 122.9, 'Philippines'],
    PK: [30.1, 69.4, 'Pakistan'],
    PL: [52.1, 19.4, 'Poland'],
    PT: [39.6, -8.2, 'Portugal'],
    PY: [-23.2, -58.4, 'Paraguay'],
    QA: [25.3, 51.2, 'Qatar'],
    RO: [45.8, 25.0, 'Romania'],
    RS: [44.2, 20.8, 'Serbia'],
    RU: [61.5, 90.0, 'Russia'],
    SA: [24.1, 45.1, 'Saudi Arabia'],
    SE: [62.8, 16.7, 'Sweden'],
    SG: [1.35, 103.8, 'Singapore'],
    SI: [46.1, 14.8, 'Slovenia'],
    SK: [48.7, 19.5, 'Slovakia'],
    SN: [14.4, -14.5, 'Senegal'],
    TH: [15.1, 101.0, 'Thailand'],
    TN: [34.1, 9.6, 'Tunisia'],
    TR: [39.0, 35.2, 'Turkey'],
    TW: [23.7, 120.9, 'Taiwan'],
    TZ: [-6.3, 34.8, 'Tanzania'],
    UA: [48.9, 31.4, 'Ukraine'],
    UG: [1.3, 32.4, 'Uganda'],
    US: [39.5, -98.4, 'United States'],
    UY: [-32.8, -56.0, 'Uruguay'],
    UZ: [41.7, 63.9, 'Uzbekistan'],
    VE: [7.1, -66.1, 'Venezuela'],
    VN: [16.6, 106.3, 'Vietnam'],
    ZA: [-29.0, 25.1, 'South Africa'],
    ZW: [-19.0, 29.9, 'Zimbabwe']
};

/** Lowercased English name → ISO code, built once from the table above. */
const BY_NAME = (() => {
    const map = {};
    for (const code of Object.keys(CENTROIDS)) {
        map[CENTROIDS[code][2].toLowerCase()] = code;
    }
    // A handful of aliases geolocation providers actually emit.
    map['united states of america'] = 'US';
    map['usa'] = 'US';
    map['great britain'] = 'GB';
    map['uk'] = 'GB';
    map['czech republic'] = 'CZ';
    map['south korea'] = 'KR';
    map['korea, republic of'] = 'KR';
    map['republic of korea'] = 'KR';
    map['viet nam'] = 'VN';
    map['russian federation'] = 'RU';
    map['iran, islamic republic of'] = 'IR';
    map['taiwan, province of china'] = 'TW';
    map['hong kong sar china'] = 'HK';
    map['turkiye'] = 'TR';
    map['türkiye'] = 'TR';
    return map;
})();

/**
 * Resolve a `country_s` value to a plot point.
 *
 * @param {string} value ISO alpha-2 code or English name.
 * @returns {{lat:number, lon:number, name:string, code:string}|null} Null when unknown —
 *          the caller reports how many sessions could not be placed rather than dropping
 *          them silently.
 */
export function locate(value) {
    if (!value) {
        return null;
    }
    const raw = String(value).trim();
    const code = raw.length === 2
        ? raw.toUpperCase()
        : (BY_NAME[raw.toLowerCase()] || null);
    if (!code || !CENTROIDS[code]) {
        return null;
    }
    const c = CENTROIDS[code];
    return { lat: c[0], lon: c[1], name: c[2], code: code };
}

/** Display name for a country value, falling back to the raw value when unmapped. */
export function countryName(value) {
    const hit = locate(value);
    return hit ? hit.name : String(value || '—');
}
