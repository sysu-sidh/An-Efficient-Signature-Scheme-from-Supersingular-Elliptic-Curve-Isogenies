/*
 * ec.h
 *
 *  Created on: 2019年2月14日
 *      Author: lzj
 */

#ifndef EC_H_
#define EC_H_

#include "fp2.h"

#define TBALE_R_SIZE 20

typedef struct
{
    f2elm_t X;
    f2elm_t Z;
} point_proj; // Point representation in projective XZ Montgomery coordinates.
typedef point_proj point_proj_t[1];

void point_by_fp2(point_proj_t P, const f2elm_t x, const f2elm_t z);

// Simultaneous doubling and differential addition.
void xDBLADD(point_proj_t P, point_proj_t Q, const f2elm_t xPQ,
             const f2elm_t A24);

// Doubling of a Montgomery point in projective coordinates (X:Z).
void xDBL(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus,
          const f2elm_t C24);

// Computes [2^e](X:Z) on Montgomery curve with projective constant via e repeated doublings.
void xDBLe(const point_proj_t P, point_proj_t Q, const f2elm_t A24plus,
           const f2elm_t C24, const int e);

// Differential addition.
void xADD(point_proj_t P, const point_proj_t Q, const f2elm_t xPQ);

void get_4_isog(const point_proj_t P, f2elm_t A24plus, f2elm_t C24, f2elm_t coeff[5]);

void eval_4_isog(point_proj_t P, f2elm_t coeff[5]);

void j_inv(f2elm_t A, f2elm_t C, f2elm_t jinv);

//W = P+mQ
void LADDER_3_pt(const f2elm_t xP, const f2elm_t xQ, const f2elm_t xPQ,
                 const felm_t m, point_proj_t W, const f2elm_t A);

void xDiff(const point_proj_t P, const point_proj_t Q, f2elm_t xPQ, const f2elm_t A);

// y into z
void select_p(const f2elm_t A, const int per_r, point_proj_t P, point_proj_t Q, int *r);

//
void iso_2m_curve(const felem sk, const point_proj_t P, const point_proj_t Q, const f2elm_t xPQ, const f2elm_t A, f2elm_t out);

void iso_hash521(const felem m1,const felem m2, f2elm_t A);
void iso_hash521_E(const felem m1,const felem m2, const f2elm_t E0, f2elm_t A);

void iso_hash_N_2_N(const f2elm_t A, f2elm_t B);

void iso_hash_N_2_N_E(const f2elm_t E0,const f2elm_t A, f2elm_t B);

void iso_hash(const f2elm_t A, f2elm_t B, int chainlen);

const static f2elm_t E0_64 =
    {
        {0X11B7341501B994B0, 0X33EBAA11B599E997, 0XC41766BADFDF6346, 0X5EBC65092EF1E836, 0X300042975B1A80F1, 0XAD3DD5C3C6A6529A, 0X75DF59AB557498C1, 0XE880072ECFBFBCB9, 0XDC},
        {0XE5402058794F590E, 0X11AD706B7CFD5FDB, 0X202455377AFFBC8C, 0X36CA163EA194B8E6, 0X51144333F0BA1EA0, 0XA0697F2B574D1783, 0X0F78B5AF886F9548, 0XFF5292A2D1A2802D, 0X15A}};

const static limb table_r_sqr[20][9] =
    {
        {0xA98CC0610E19220C, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19222A, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19222F, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192234, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192239, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192243, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19225C, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192261, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19226B, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192270, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192289, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19229D, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922A2, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922CA, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922D4, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922D9, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922ED, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192306, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922DE, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192315, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0}};

const static limb table_r_qr[20][9] =
    {
        {0xA98CC0610E1921FD, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192202, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192207, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192211, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192216, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19221B, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192220, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192225, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19223E, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19224D, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192252, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192257, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19227A, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19227F, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192284, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E19228E, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192293, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E192298, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922A7, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
        {0xA98CC0610E1922AC, 0x7DED03929A29DB23, 0x09FF1E89D00DF14B, 0x0000000000000001, 0x0, 0x0, 0x0, 0x0, 0x0},
};

const static limb table_v_qr[40][9] =
    {{0xC9664C77061745E3, 0xF20CAA915A1B70A9, 0x6AB8F28B21FEE36D, 0x9DA10A3A6A8AAC28, 0xFF35AE513C4550EF, 0xA44CFE8DD5D2A635, 0xF561CED12313AA19, 0x9B6BB2E8B590D04A, 0x00000000000001A2},
     {0x73DA8B806AD0D788, 0xA6CA362E759AF12D, 0x048080C9D3CE2336, 0x6668EF55977EDCE4, 0x23CAF2F6BDAD00CC, 0xE67A6D4A0485A922, 0x9297A71130CE0C09, 0xBC0AC4BB78B93F50, 0x000000000000002F},
     {0xF84F87EF87762481, 0xF96B31319F59BE36, 0x9E51A71E4598DED2, 0x8892185330B74AD0, 0xAE38642C7EF1A111, 0x60F9DFC74B3E6EC3, 0xEAD08E985FD65139, 0x44A59D2E6117B4AE, 0x00000000000001C2},
     {0x604DB57CF5494A98, 0x65FFD0DB293A0FEA, 0xFBE97C7A102552CE, 0x6FE100661D11E6E3, 0x1505BFE3FF29A280, 0x4C81C8FFA5E24D4C, 0x3D93C042111B8BE7, 0x927A457A9A2DE950, 0x000000000000017D},
     {0xB1140C2A322F46D2, 0x178A9B5C8B2D55F9, 0xEA67530E40E6F9EA, 0xB1C68FA2ACFCAFFC, 0x8E06EC186F7CC57C, 0xF1EDD341501E80F4, 0xD5454F3CAA81233F, 0xF59A62FEE158429F, 0x0000000000000086},
     {0xBCD9CF4D2E837D70, 0xA5FFFA24D8E6D473, 0x254473A9DA9597D3, 0x14853E56CFBA3012, 0xF319A9B32F9FEE21, 0xBD4CEDBCB5E03BAC, 0x338882716DE49B9A, 0xBCAC43F16EC9D4CB, 0x0000000000000046},
     {0xE544CC8680F798AC, 0x559BAFF259C0BFA6, 0x858D8366CA72BDA7, 0x56AE62CDE37D24BA, 0x64F8CC8EE225B078, 0x074EB2915685958F, 0x5BB047DD00B4EEE2, 0x5D5C35613C65C142, 0x00000000000001DA},
     {0x8E74A09C610598E7, 0x74AE164735E52848, 0xEFBC848F0C58B31B, 0x46A810AB02646301, 0xBFD620F539F4D704, 0x6F1D6A6317053BAE, 0xE7F93CCB258D19CB, 0xD03A317EA09ABD23, 0x0000000000000007},
     {0x27DF29F4D1C18237, 0x365395D318C68732, 0x585C990133C0DC1A, 0x8E0A153552D1A633, 0x2E06F2AFF20D1CFB, 0x81299F7C9D03CB6D, 0x9A5CDB16433D7522, 0x9276BFDF030C5895, 0x00000000000000F4},
     {0xD95855481AE245E2, 0x28980171207D80ED, 0x1E002DF4B9FBFCC9, 0x0D6D0A160181184C, 0xFABE8509777E71E6, 0x58B7844757F56812, 0x1A3C6994BC4FC6E3, 0xAEBA0219165C2D1D, 0x0000000000000096},
     {0xA119AA7638AD0E08, 0x7B63F622C5D57AA9, 0x035F3F38E2C43698, 0xD1B68594B9303429, 0x3B5F8F44B9B5C554, 0xF32BFAFA9A1953A8, 0xA1DB838E7831DFDE, 0x0ED82DA07050D1D7, 0x0000000000000125},
     {0xA4210553D77D8701, 0x4D94075E92153DD3, 0x4630D89A88276F7B, 0x978B913EA9DEE9C2, 0x344A1776160DFB33, 0xAC2105E73C684CF5, 0x820B92A06C0D323C, 0x207A7FFA199B7F46, 0x0000000000000157},
     {0xA2A8B54A3613300A, 0x9466564BCCC55DB4, 0x690A0E905EBCD1C6, 0x9F5CA7B148AF658D, 0xA514C87DBF8C799C, 0x4BD3334B43F976E9, 0x12B6B6FD34D40A9F, 0xF5F94C76C9EC0D79, 0x0000000000000086},
     {0x66F3088AB39D57FC, 0x80F5C9EE2146076B, 0xED7BEB47C57DF7FE, 0xE2F1A9FF07F66609, 0xF159B9186BF12F30, 0xBEDF58833FAE4DEF, 0x8BCD2C71B70438FE, 0x23BECE0DB5A4FA8D, 0x00000000000001A6},
     {0x1C31E0D756B558C6, 0x8863C34A70D4DD1E, 0x2E5F0DCF3753040E, 0x472F7E05AC7ECB46, 0x2668EB24F61D919B, 0x45741B1D7422EADA, 0x410FA0F015FD9610, 0xF0860B8CC25196F6, 0x0000000000000014},
     {0xE430F9892230E9FC, 0x6D140D614226E2E6, 0x47FD932D5FCE9C06, 0x78BFAD81091F1CD0, 0x368A6CD84550987A, 0x473A04CA810DD150, 0xB5526EEADF227C4F, 0xCC7E5CF11ABB6645, 0x00000000000001A2},
     {0x5432780203A4F80E, 0x8594B02A7D66ED3E, 0x603C2E4E2C7E07EE, 0xD9A1E388F6060258, 0x3A0A4268A149853C, 0x365A6B2982EAF281, 0x1F5E5DE182A2D2F2, 0x86C91BF5EFF10B93, 0x0000000000000017},
     {0x75E488FFDBEEB7C5, 0x47D59E26EFBB5C34, 0x764BDFF463ADB1E3, 0xF4575B5609BF41B3, 0x37E8AF9113077803, 0x32CDBC40497C1735, 0x3A4F69D0D7D4DC1D, 0xD77FB937DA8D6947, 0x000000000000010C},
     {0xCA078045C21C2E54, 0xC86FD8AFE2CB11F9, 0x14C349CBDCC57F52, 0xFC97701E362D6405, 0x322FDE965B27E3DA, 0xBBE89E5361E22831, 0x2C4EA05C810CB2C2, 0x5641F52268B60923, 0x00000000000001B2},
     {0x9E080574FF7151D4, 0x55332E8BCA6E8246, 0x7223B6986F344A9C, 0x2414F2247160ECFE, 0xB9F652A6CD0E3740, 0xDD13030B6F584796, 0xF1D92E24BD34B60B, 0x4554787908A050B0, 0x00000000000001B0},
     {0xDBF25B92CD0E83CF, 0xF4BBAC8C13ADEB5E, 0x6165621583484207, 0x94663FFAFC7CE5E8, 0x42F03DD30BAECCD1, 0x333C2EDE8D383FDB, 0xCF9AAC62C7AB5D39, 0x1D1465A620ACF679, 0x000000000000006E},
     {0x0BF5E4351FFCE8DA, 0x3047DB31E1878556, 0x6E67711C9B0F9E71, 0x0A1A97D3FF8B1E38, 0xB740B0A33626D141, 0x3491847FB3E851A3, 0x28C73796B65A7A4D, 0x38CEADD810071FD7, 0x00000000000001D9},
     {0x32769E204EF4A6AA, 0x44671533682702CC, 0x37CD0AAF31232D26, 0x44720C241E11463F, 0x3808C8CA95186D96, 0x1C116321859781AC, 0x39169357591A45EE, 0xEDC40BDA434750C9, 0x00000000000000D6},
     {0x69D9064552075AB3, 0xF20C2F5A17FB97BA, 0x970A75F7C8CB3534, 0x372FDE7FCB2B5770, 0xBCFA7D66277CF145, 0xC4388D035961D89C, 0xA71ABE89D060D958, 0x78C81588325B76F4, 0x0000000000000169},
     {0x0DD003720BC27BE9, 0xF2F72B7704C630F5, 0x734D652F3B6D4491, 0x28BDB8187C874C49, 0xA52A2A6D42A43117, 0x08924F21FC6C6A5E, 0xDABD853B9AD7A5A3, 0x6D3C9E6F478B3C8D, 0x00000000000000B6},
     {0xB407F7728D2C0A73, 0xFBCE06520B722433, 0xA27FA468CB96C10F, 0xA61CA945ED01BCF2, 0x9C100E9EB78135DA, 0xAA710918F5B82FA4, 0xD2869AF0D6E1FBA7, 0x33A0521C58F41A27, 0x00000000000001BF},
     {0x62004BC1E7BD15CD, 0xFF10B8713029C030, 0x792AC58CE1CD55DF, 0x3F9CFBDE6A061367, 0xECAA0033FE41E0F0, 0xB5D32C293BED04DA, 0xCC115A2699A92566, 0xC00AC367969B828B, 0x00000000000001DA},
     {0xB283759AAFCD1B7A, 0x770420BB76E5645D, 0xD0BF77E38EC5FAC1, 0xA0F247296839F2DF, 0x0F5033DD4D394688, 0x8E78BC086140FE2D, 0xB984D23DA80ABC7E, 0xF312732343437DFA, 0x0000000000000038},
     {0x740D607F717E5783, 0xD6AB6ACC90432521, 0x0C581BDC02B8FF38, 0xF04E291AE852D686, 0xE3432BC0C5891CF5, 0xE413128AB8394A42, 0x83BC046B696455D3, 0x5E1F49150D52643A, 0x0000000000000147},
     {0x0BFC5759A27F5262, 0x8A85B51D2CC23830, 0xE71D1A8104A0B33E, 0xA81C00A6964FF3B5, 0xEBCC553A20E30ABD, 0x163C81967318275E, 0x0C3EF1F22098C98B, 0x52934882E486D03D, 0x0000000000000128},
     {0x6A4395DD6901F506, 0xF8E221DC30A190F6, 0x5F820EDCB70F5C5A, 0xAF6FF5F08A8CBC9B, 0xBA5D79FCA4F0BFE3, 0x244E7E37A9387228, 0x83D43A337E022AF4, 0x2496C04F615000CE, 0x000000000000017F},
     {0x6133BC322939F4B4, 0x7FDE159F59F71FDF, 0x586CC70D6D889FB3, 0xF940BA262BF5BF5B, 0xE7F521335755BDA9, 0x582FFA65C16FE881, 0x62EDDB31D7E1C01C, 0xD6609C8CD86B0D9A, 0x000000000000006B},
     {0x8768CBBB23CCD360, 0x0CF07031B65607EB, 0x5E36AC9F1F9C56C7, 0x053F9A683CA390BB, 0xEAA880BE6D02FCAD, 0x8E9EF2A20466F809, 0x02B4E8C178E7681B, 0xA1D556F17C87C517, 0x0000000000000140},
     {0x412075EA2F7BC5A4, 0x7D8F1BBFDD08C7E1, 0xD2E105B6DCC1328B, 0xF7B7984E6D936423, 0x2170A329C4268B4B, 0xA89C7B5D8EFC1F75, 0x28194AC428BBB7AF, 0xC5ABD302FFCA8DF2, 0x00000000000000EB},
     {0xF5E5447868FAD023, 0x696BF8633B6CD6A1, 0xBCD5769361F1ABEE, 0x0A1B3BA88EEA338F, 0xFD5B29EB5968F3A4, 0x5D06800792002C06, 0x2580849C8DEE0B1D, 0x68698340B6C71DDD, 0x0000000000000044},
     {0xDD7020BF8BEC4359, 0xE573E79721AA54B0, 0x33C27574AB6A0598, 0xDE436AC9D479CBC2, 0xCC21C6DF75B0C029, 0x3762C8FA2004A365, 0xE5338314C12AE27F, 0x9BDF296AEFB74F39, 0x00000000000000CD},
     {0xC6165E0093F38538, 0x751511CB8F549192, 0x709D79C0333AE9EC, 0x95BBDAA129D2825E, 0x7D01B8500849EBC9, 0x7EE44665F9FF5C25, 0xA3E81F37F1585AB6, 0x8151BCD8468CB71E, 0x0000000000000004},
     {0x3A117B598AB68AC6, 0xD1AEA4BB84B0E489, 0xF66E91942BF04E48, 0xA473B8D093905909, 0x1DCD3FB96BF65E4C, 0x9AD5512A53FA84AF, 0xCAB2B5AC3DBD9169, 0xC38373A7C19C97DD, 0x0000000000000028},
     {0x36492662C243D901, 0x9E17BA78F3E59106, 0xDDD89B25AA4B93EA, 0xB3A2139A93B14339, 0x397005153848EA08, 0xA1AB79DA15535F5D, 0x3C7E8FB5131642B0, 0x08DB16CE0BC350E5, 0x0000000000000030},
     {0x6CDD744A5B21563F, 0x491B6B63BDAE7739, 0x60F55F95E4B5C018, 0x8192BA974ADBEB6E, 0xAF0BBF229E3B1C3B, 0xF50EB4937E5919E8, 0xA2296A66F897390A, 0xF50E14AD1588559C, 0x00000000000000D5}};

const static limb table_v_sqr[40][9] =
    {
        {0xBFEA050B98348FE2, 0x4198CD6F25F5A851, 0x10C96EE2CF21C1F4, 0x171FCA75C5194D20, 0x8CF8B43210F49901, 0x5FE69E368E00E9F7, 0x3210CE75FBE57A2A, 0xDF3661C32D1200DC, 0x0000000000000179},
        {0x45678554820E3155, 0x16418BE9E1B5126A, 0xF60CCF0928306EB5, 0x71E33793CC512AA0, 0x9B4F6FC61F52B260, 0x792C21DC11E5ABAC, 0x033AB65F255792D7, 0x44B9B537332314FE, 0x00000000000000A0},
        {0x6585E5228379BF7C, 0x782608D41B7DE291, 0xF5AB89E7179A8E16, 0xD04466E59D3DA433, 0xA7A559E16CEC20DF, 0xC64CAC8D72039550, 0x0CF209ED66B6B1E1, 0xC38D07D2FCF9D587, 0x0000000000000199},
        {0xD52B334545F8B12E, 0x12570221AF12F09F, 0x95E398816C6D3CC9, 0x642D39B39B501DA2, 0xD6D969B8420D2C06, 0x497C0D503CD3F255, 0xCCACDB48BC82A290, 0x9C9FBD5946D578B5, 0x00000000000001F7},
        {0x7842C897DA4DDB42, 0x321E437A50E40DED, 0x95FAAB51A77FA399, 0x7307091191CB07DB, 0x8B4A7FB2F401895B, 0x5D5528C27FAE89C6, 0x32125A3A837C3200, 0x6026C5FE2E96A9BE, 0x0000000000000037},
        {0xB230F22A640EA6C4, 0xE3768A058E2950BA, 0xA272ED867B542904, 0xA0A37AFD109757F5, 0x377530607311CA8F, 0x794921C962858C31, 0x57301C28976C4545, 0x84AC2F8C278C3362, 0x000000000000014E},
        {0xD8239F44A5E561A0, 0xD6B5CC0B73AC626D, 0x9020074B013472CB, 0xAB76B2704A1F8020, 0x8325924425048D11, 0x5D776870194F3CD1, 0x289C5049E8C3B822, 0xF1E06251CF833F84, 0x00000000000001C4},
        {0xE4659786661DBA09, 0x07D598DB3602FF1D, 0x32A851E0380B5D38, 0xF029147F072EAD14, 0x0BD9562A8E2D7F1B, 0x83210A1157A0D53A, 0xF052D88BBDEB954E, 0xF17C5031E760FEB9, 0x00000000000001E7},
        {0x7AB930E4A9F33D28, 0xB1054D51FEDCAD45, 0xBFDAFF6327E0A60E, 0xA6C9195853172641, 0x7AAEC417E4F40FF3, 0x57970B478BA1D973, 0xE6CE3083938A5CB2, 0x1CA8B62D25473392, 0x0000000000000113},
        {0x96F67D464DAB2B48, 0x26CD3C98876C4D19, 0x853CC44F432BD658, 0x87E82D6771DCCF55, 0xA8A709995B73BD65, 0x53596A8106037F66, 0x3DAC38BC335DFD6F, 0x3918F9E246105C95, 0x0000000000000048},
        {0xE662A4F5567C5710, 0xFAFF3145B29645AB, 0x7CB25E05C5DEB645, 0x55D3F2A3C348BB11, 0xD1F15D591F7D4C9E, 0xA3E17E3315778165, 0x79EFDB1F6F40C286, 0xD441C3782C7A7C75, 0x000000000000009B},
        {0x21BDBD8F4A901D2F, 0xB15F0A674AB8628D, 0x3BD70C704AADEA4C, 0x6D8C3E5A2DCF402A, 0x3157E68B0F513BF2, 0x53159022D87A0A12, 0x7D163DDB07238058, 0x96F6C4C8099D72A8, 0x00000000000000A2},
        {0x1148404E24B8361A, 0xA7996B09177F4814, 0x65DF624A2144820B, 0xAF18127EF4352246, 0x223ED22119F34B62, 0x9DC272F2C0DA13AD, 0xDC52933BB85CA7DD, 0xA8ECFF66AB6E00CF, 0x0000000000000021},
        {0xE56828A53672BFF7, 0xC1AF3DB50E604AEF, 0x68525B97E2D0B3D7, 0x204C5999D1414B5F, 0xF414EB1E661D6A8D, 0x27A42A7A914A613D, 0xEF478E7A19267841, 0xAD5B7F6E572E68CC, 0x000000000000012F},
        {0xE982315D61A6F2A8, 0xB988D9A36D1A2A40, 0x062C2BF86C5CD453, 0xB56C76BDB3524857, 0x41829BA7C19ABC12, 0x08477775B395A85D, 0x5C3C14A87A2A34CB, 0x3C9B450BC080FA55, 0x0000000000000072},
        {0x1E5CF4A54A3B84E7, 0x0E18B3B2B6643C7D, 0xC0A5383B78C210A5, 0x42BE8CA81943E32A, 0x07487FF1F0D911EA, 0xB771181E624F47CD, 0x3B5FC5499E9F2DDD, 0xDBBF53D3BA6F8046, 0x00000000000001E2},
        {0x67AF02EA4482D155, 0x5D8AFD9D0C050551, 0xAB8EF404872ADCE8, 0xAB404FA8D9F762CE, 0x6564E349C2DC9C90, 0xFAB9A8FFE4617F9E, 0x930608B5CC59C532, 0xC6BA2A5E17B470A7, 0x000000000000007A},
        {0xD18501566075AFA5, 0x1A1333BE06DBFF99, 0x86F95EFDEDBC64BF, 0x94003A7E2E303135, 0xA8E39FF51BE6D12C, 0x50599FAA752E6098, 0x686A87966483D2CC, 0x07D9DBF6ADB0A72D, 0x000000000000019F},
        {0x09510E7A9156B97B, 0x5606B92D9DC4B683, 0x5B14AD20E8D62043, 0x68DA9D5F2E3E1815, 0xD26A05B648F3D70D, 0xF4F99B8CC7ECA3F9, 0x12C4EAA0DEB583A1, 0xE97440D68541542C, 0x00000000000000C2},
        {0xD000BCA9399D0579, 0xE3994E155862EBFF, 0xE1B5792A02B915AD, 0x97B098D5D36C0AF4, 0xD6613447836B7F7E, 0xB2224F17CD687445, 0xF19D60948DA4A101, 0x2137C2E1C9BA7E0D, 0x00000000000000F6},
        {0x043F5EA418AC47C7, 0xB9EBA8FA200FA508, 0x1CFBEBE52BECD3CC, 0x465C73300C05AF17, 0xB7FD764981DFC04F, 0x505F7573CE462A2C, 0xFE23F0AD7E0D11EA, 0xD2A5540A88F24907, 0x00000000000000D9},
        {0x9B6AB096F83454B4, 0xD16EC080A67F27E2, 0x45FED16C9767329C, 0xCF463FFF4F771B2F, 0xD3E70B244C9DAD63, 0xE087F67425AC6A7A, 0x3D9B9006F44EB95A, 0x600B2C11D66568FA, 0x00000000000001EC},
        {0x2DBA5F96C190C4BD, 0x39B286ECCBAC08AF, 0x3B307F59924A6FFB, 0xA6BB1072F1DC2EA1, 0x6B63DAB24F28051A, 0x619470D83EE62662, 0x1502423014147124, 0xE860637068BCA3C4, 0x00000000000000B9},
        {0x2E4A1E4DC1989995, 0x590AACFE207C1F69, 0x1431B85036DD47FF, 0xD7B35A666710AAFD, 0xEDE09E81A58D75BD, 0x739940F52F769E01, 0xC34EC2BEDA09AFF5, 0x9139541A584A292C, 0x000000000000011C},
        {0x95FB6C635772E1BD, 0x4B68DEFCE4B4D607, 0x382804FEDCF291FC, 0xB5503C86E15030AA, 0xDE5FB151877A8CCD, 0xF5363FF5493D6807, 0xE2E2F4A892455F4A, 0xEB33636FFDBBB8C9, 0x000000000000014F},
        {0xA08E0744DDF40D7D, 0xE12B2E3298807E2F, 0x508E205007583340, 0x78D256B10F288AE1, 0xB5B4E1E6069BE74D, 0xE0DA2F03406A3AA1, 0xBD61AAA88CF35D85, 0xFA6CDCFE6A286E71, 0x000000000000013E},
        {0x2C89004063E37E48, 0xFFF1FA67354BEEA6, 0x835AB839556BA3D0, 0xCD3A524E482D5D7E, 0xF029FC59B0027E46, 0x41E9C422E94873A4, 0x654EA71A2D790D32, 0x0233EDE54DC1424D, 0x0000000000000021},
        {0x182DA2B366A0F81C, 0x782D1C627F9AE56F, 0x29A38EDD4EA099D7, 0x95B26ABE4F994874, 0xB3BAA3A20800835C, 0x1BDEE9FC4B53E1C0, 0x5E8A7CDD1F981DB7, 0xF5D331AEADCF34AB, 0x00000000000001B5},
        {0x82BADA40391C1044, 0x35B5F8559318941F, 0xDD812824E4BCAD76, 0xB5A7620A6215D553, 0x88524C6027DF5A89, 0xB82B794FFBE6205A, 0x36E141458EB8E6E4, 0xF4CC3ECBD91FDABE, 0x00000000000000F4},
        {0xAACFEDB97FB85A90, 0xC2360B2953B4E1A1, 0x2D32E706125BD970, 0xB7B7C85E810D9857, 0xAD14C0C8631D4291, 0xB2E92E90D163967E, 0xA4BF01EBBE2ADDB9, 0xC14EAB46BE2F8BF5, 0x00000000000000C0},
        {0x16B7E0C80DD9BD4A, 0x56C00F746D952091, 0xE2A7BB40A3F3A50A, 0x36DD6371C84AE34C, 0xEC507AD36EC76079, 0xACFB7F2ECA9916A6, 0xAC3B15F7B64BE65F, 0xFA82CFC56FA046F7, 0x0000000000000155},
        {0xABDF63C5D26A8D3C, 0x5A2AD9EF5B77F302, 0xC32FB5A65F1AE7CB, 0xAB6F5F05763984CF, 0xAFBD970EF4E59A9C, 0xE0F2784C724652B7, 0x88267FA73F5BA620, 0xCBF8C2880DE3F1F3, 0x00000000000000C1},
        {0xD3CFEC0209D3EA5C, 0x0BBEEAE84AE287D7, 0x3D2970ADBF282777, 0x9E789B82CC869A2C, 0xFD44ECC63174414F, 0x6936D4B588208B01, 0xED8D1E93E095B184, 0x6FAD246DA5D53BE2, 0x0000000000000104},
        {0xCD453CFA79118E0E, 0x6A738EB205D713BE, 0xD7716CF6AA9D99BC, 0x2F67B88D4A419946, 0x3EC78F565B76BC1A, 0x98074E5F052E57AB, 0x88026357BE48FB6F, 0x698EB938EC67C10A, 0x00000000000000AD},
        {0xBF1E5B97FF8683F8, 0x16A1696808A466FD, 0xCC1153C3CA6864E4, 0x49C6BF8CB040AF07, 0x279C6557C2231DE3, 0x55FC285C0D3D44F0, 0x093E86A13C413E01, 0x95D8FFBF43C3D017, 0x00000000000001A7},
        {0xCC638E92DBC81922, 0x5610D15CEC9D3167, 0x7B4E256D529938D9, 0x194889EA5399C8A1, 0x4D971103BC9D4190, 0x4DE440FDA0440FFF, 0x63549BF8B829E3E8, 0xD919C80C2EFD378E, 0x00000000000001AB},
        {0x0A44912C5AC4AB19, 0xAD8577E2D4F777C7, 0xD11DBB649A76E8E1, 0x188CC254D541D341, 0x2BED783FED44B5AC, 0xA6DF8F45FD2C547F, 0xDE6D95E3C9DD3C34, 0xB6F2BACD0F841646, 0x00000000000001C7},
        {0x8C343216C1C0EFF1, 0x0C044078FCD68E89, 0x60818CF37E269D65, 0x5B11D87A521B00B7, 0xCC20CA29F65D386F, 0x4E652B0D37CE0B00, 0x13776BBA1399B3AF, 0x2E7467B1F5688270, 0x00000000000000DF},
        {0x50951B0F3DD84ED7, 0xAFB7B9C4FD483448, 0xD01E33EF1A4A19E7, 0x3851318979E86F81, 0x7D7A2F420EBE1BF6, 0x31D593EC1C5A53C0, 0x11E1353C49C080AB, 0xD7CCC84CF07A080C, 0x0000000000000113},
        {0xE97CDE9AAC40CA7B, 0xD6F4A6D226A1025E, 0x1F6C3A3CC1C6F128, 0x8780D153C153FC1E, 0x996A80AD6BFC2A9A, 0xC31048A1BF128917, 0x9ED0D3390C5963E3, 0xF6958337E00FB537, 0x00000000000000C4}};

#endif /* EC_H_ */
