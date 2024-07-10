/*
  Example of a comparison between integers in BGV
 */

#define PROFILE

#include <chrono>
#include <fstream>
#include <iostream>
#include <iterator>

#include "openfhe.h"

using namespace lbcrypto;


// Duhyeong: Copy & Paste & Minor-edit from longDiv in src/pke/include/scheme/ckksrns/ckksrns-utils.h
struct longDivMod {
    std::vector<int64_t> q;
    std::vector<int64_t> r;

    longDivMod() {}
    longDivMod(const std::vector<int64_t>& q0, const std::vector<int64_t>& r0) : q(q0), r(r0) {}
};

// Duhyeong: Copy & Paste & Minor-edit from Degree in src/pke/lib/scheme/ckksrns/ckksrns-utils.cpp
uint32_t Degree(const std::vector<int64_t>& coefficients); 

// Duhyeong: Copy & Paste & Minor-edit from LongDivisionPoly in src/pke/lib/scheme/ckksrns/ckksrns-utils.cpp
// Need assumption that the BGV ptxt modulus is prime
std::shared_ptr<longDivMod> LongDivisionPoly(const std::vector<int64_t>& f, const std::vector<int64_t>& g, const NativeInteger& p);

// Duhyeong: Copy & Paste & Minor-edit from AdvancedSHECKKSRNS::EvalLinearWSumMutable in src/pke/lib/scheme/ckksrns/ckksrns-advancedshe.cpp
Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                                               const std::vector<int64_t>& constants, const size_t& numslots);

// Duhyeong: Copy & Paste & Minor-edit from AdvancedSHECKKSRNS::InnerEvalPolyPS in src/pke/lib/scheme/ckksrns/ckksrns-advancedshe.cpp
Ciphertext<DCRTPoly> InnerEvalPolyPS(ConstCiphertext<DCRTPoly> x,
                                                         const std::vector<int64_t>& coefficients, uint32_t k,
                                                         uint32_t m, std::vector<Ciphertext<DCRTPoly>>& powers,
                                                         std::vector<Ciphertext<DCRTPoly>>& powers2, const size_t& numslots);

// Duhyeong: Copy & Paste & Minor-edit from AdvancedSHECKKSRNS::EvalPolyPS in src/pke/lib/scheme/ckksrns/ckksrns-advancedshe.cpp
// It seems like only working for degree >= 5
Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients, const size_t& numslots);


Ciphertext<DCRTPoly> EvalComp(ConstCiphertext<DCRTPoly> x, ConstCiphertext<DCRTPoly> y, const size_t& numslots);


int main(int argc, char* argv[]) {
    ////////////////////////////////////////////////////////////
    // Set-up of parameters
    ////////////////////////////////////////////////////////////

    std::cout << "\nThis code demonstrates the use of the BGVrns scheme for "
                 "homomorphic comparison. "
              << std::endl;

    // benchmarking variables
    TimeVar t;
    int64_t processingTime(0.0);

    // Crypto Parameters
    // # of evalMults = 3 (first 3) is used to support the multiplication of 7
    // ciphertexts, i.e., ceiling{log2{7}} Max depth is set to 3 (second 3) to
    // generate homomorphic evaluation multiplication keys for s^2 and s^3
    CCParams<CryptoContextBGVRNS> parameters;
    // parameters.SetRingDim(32768);
    // parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetMultiplicativeDepth(17);
    parameters.SetPlaintextModulus(65537);  // 786433, 536903681
    parameters.SetMaxRelinSkDeg(3);
    parameters.SetNumLargeDigits(5);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);

    std::cout << "\np = " << cryptoContext->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
    std::cout << "n = " << cryptoContext->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder() / 2
              << std::endl;
    std::cout << "log2 q = "
              << log2(cryptoContext->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble())
              << std::endl;

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Perform Key Generation Operation

    std::cout << "\nRunning key generation (used for source data)..." << std::endl;

    TIC(t);

    keyPair = cryptoContext->KeyGen();

    processingTime = TOC(t);
    std::cout << "Key generation time: " << processingTime << "ms" << std::endl;

    if (!keyPair.good()) {
        std::cout << "Key generation failed!" << std::endl;
        exit(1);
    }

    std::cout << "Running key generation for homomorphic multiplication "
                 "evaluation keys..."
              << std::endl;

    TIC(t);

    cryptoContext->EvalMultKeysGen(keyPair.secretKey);

    processingTime = TOC(t);
    std::cout << "Key generation time for homomorphic multiplication evaluation keys: " << processingTime << "ms"
              << std::endl;

    ////////////////////////////////////////////////////////////
    // Encode source data
    ////////////////////////////////////////////////////////////

    // Duhyeong: Cannot find an API to set # of slots in the BGV context...
    size_t numslots = 12;

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    std::vector<int64_t> vectorOfInts2 = {1, 8, 3, 5, 10, 14, 30, 0, 4, 15, 17, 10};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);

    std::cout << "\nOriginal Plaintext #1: \n";
    std::cout << plaintext1 << std::endl;

    std::cout << "\nOriginal Plaintext #2: \n";
    std::cout << plaintext2 << std::endl;


    ////////////////////////////////////////////////////////////
    // Encryption
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning encryption of all plaintexts... ";

    std::vector<Ciphertext<DCRTPoly>> ciphertexts;

    TIC(t);

    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext1));
    ciphertexts.push_back(cryptoContext->Encrypt(keyPair.publicKey, plaintext2));

    processingTime = TOC(t);

    std::cout << "At level = " << ciphertexts[0]->GetLevel();

    std::cout << "... Completed\n";

    std::cout << "\nAverage encryption time: " << processingTime / 7 << "ms" << std::endl;

    
    ////////////////////////////////////////////////////////////
    // Homomorphic Polynomial Evaluation
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning homomorphic poylnomial evaluation based on the Paterson-Stockmeyer algorithm...";

    std::vector<int64_t> coefficient = {1, 3, 5, 8, 10};
    auto ciphertextPolyEval = EvalPolyPS(ciphertexts[0], coefficient, numslots);  

     std::cout << "Completed\n";

    Plaintext plaintextPolyEval;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextPolyEval, &plaintextPolyEval);
    plaintextPolyEval->SetLength(plaintext1->GetLength());
    std::cout << "\nResult of homomorphic polynomial evaluation: \n";
    std::cout << plaintextPolyEval << std::endl;  

    ////////////////////////////////////////////////////////////
    // Homomorphic Comparison
    ////////////////////////////////////////////////////////////

    std::cout << "\nRunning homomorphic comparison ...";

    auto ciphertextComp = EvalComp(ciphertexts[0], ciphertexts[1], numslots);  

     std::cout << "Completed\n";
     
    Plaintext plaintextComp;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextComp, &plaintextComp);
    plaintextComp->SetLength(plaintext1->GetLength());
    std::cout << "\nResult of homomorphic comparison: \n";
    std::cout << plaintextComp << std::endl;  
    std::cout << "At level = " << ciphertextComp->GetLevel() << std::endl;


    return 0;
}

uint32_t Degree(const std::vector<int64_t>& coefficients) {
    const size_t coefficientsSize = coefficients.size();
    if (!coefficientsSize) {
        OPENFHE_THROW("The coefficients vector can not be empty");
    }

    int32_t indx = coefficientsSize;
    while (--indx >= 0) {
        if (coefficients[indx])
            break;
    }

    // indx becomes negative (-1) only when all coefficients are zeroes. in this case we return 0
    return static_cast<uint32_t>((indx < 0) ? 0 : indx);
}

std::shared_ptr<longDivMod> LongDivisionPoly(const std::vector<int64_t>& f, const std::vector<int64_t>& g, const NativeInteger& p) {
    // for (size_t i = 0; i < f.size(); i++){
    //     std::cout << f[i] << ", ";
    // }
    // std::cout << std::endl;
    // for (size_t i = 0; i < g.size(); i++){
    //     std::cout << g[i] << ", ";
    // }
    // std::cout << std::endl;

    uint32_t n = Degree(f);
    uint32_t k = Degree(g);

    if (n != f.size() - 1) {
        OPENFHE_THROW("LongDivisionPoly: The dominant coefficient of the divident is zero.");
    }

    if (k != g.size() - 1) {
        OPENFHE_THROW("LongDivisionPoly: The dominant coefficient of the divisor is zero.");
    }

    if (int32_t(n - k) < 0)
        return std::make_shared<longDivMod>(std::vector<int64_t>(1), f); 

    std::vector<int64_t> q(n - k + 1);
    std::vector<int64_t> r(f);
    std::vector<int64_t> d;
    d.reserve(g.size() + n);

    while (int32_t(n - k) >= 0) {
        // d is g padded with zeros before up to n
        d.clear();
        d.resize(n - k);
        d.insert(d.end(), g.begin(), g.end());

        q[n - k] = r.back();
        if (g[k] != 1){
            NativeInteger gk = g[k];
            NativeInteger qnk = q[n - k];
            auto gk_inv = gk.ModInverse(p);
            qnk = qnk.ModMul(gk_inv, p);
            q[n - k] = (uint64_t) qnk;
        }
        // d *= qnk
        // std::transform(d.begin(), d.end(), d.begin(),
        //                std::bind(std::multiplies<int64_t>(), std::placeholders::_1, q[n - k]));
        for (size_t i = 0; i < d.size(); i++) {
            NativeInteger qnk = q[n - k];
            NativeInteger di = d[i];
            di = di.ModMul(qnk, p);
            d[i] = (uint64_t) di;
        }
        // f-=d
        // std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<int64_t>());
        for (size_t i = 0; i < r.size(); i++) {
            NativeInteger ri = r[i];
            NativeInteger di = d[i];
            ri = ri.ModSub(di, p);
            r[i] = (uint64_t) ri;
        }
        if (r.size() > 1) {
            n = Degree(r);
            r.resize(n + 1);
        }
        if(n == 0 && k == 0 && r[0] == 0)
            break;
    }
    // for (size_t i = 0; i < q.size(); i++){
    //     std::cout << q[i] << ", ";
    // }
    // std::cout << std::endl;
    // for (size_t i = 0; i < r.size(); i++){
    //     std::cout << r[i] << ", ";
    // }
    // std::cout << std::endl;
    return std::make_shared<longDivMod>(q, r);
}

Ciphertext<DCRTPoly> EvalLinearWSumMutable(std::vector<Ciphertext<DCRTPoly>>& ciphertexts,
                                                               const std::vector<int64_t>& constants, const size_t& numslots) {
   
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(ciphertexts[0]->GetCryptoParameters());
    auto cc   = ciphertexts[0]->GetCryptoContext();
    auto algo = cc->GetScheme();

    if (cryptoParams->GetScalingTechnique() != FIXEDMANUAL) {
        // Check to see if input ciphertexts are of same level
        // and adjust if needed to the max level among them

        uint32_t maxLevel = ciphertexts[0]->GetLevel();
        uint32_t maxIdx   = 0;
        for (uint32_t i = 1; i < ciphertexts.size(); i++) {
            if ((ciphertexts[i]->GetLevel() > maxLevel) ||
                ((ciphertexts[i]->GetLevel() == maxLevel) && (ciphertexts[i]->GetNoiseScaleDeg() == 2))) {
                maxLevel = ciphertexts[i]->GetLevel();
                maxIdx   = i;
            }
        }

        for (uint32_t i = 0; i < maxIdx; i++) {
            algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
        }

        for (uint32_t i = maxIdx + 1; i < ciphertexts.size(); i++) {
            algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
        }

        if (ciphertexts[maxIdx]->GetNoiseScaleDeg() == 2) {
            for (uint32_t i = 0; i < ciphertexts.size(); i++) {
                algo->ModReduceInternalInPlace(ciphertexts[i], BASE_NUM_LEVELS_TO_DROP);
            }
        }
    }

    // Duhyeong: Cannot find ctxt-const mult API for BGV...
    std::vector<int64_t> vec(numslots, constants[0]);
    Plaintext pt;
    pt = cc->MakePackedPlaintext(vec); 
    Ciphertext<DCRTPoly> weightedSum = cc->EvalMult(ciphertexts[0], pt);

    Ciphertext<DCRTPoly> tmp;
    for (uint32_t i = 1; i < ciphertexts.size(); i++) {
        // Duhyeong: Cannot find ctxt-const mult API for BGV...
        std::vector<int64_t> veci(numslots, constants[i]);
        Plaintext pti;
        pti = cc->MakePackedPlaintext(veci); 
        tmp = cc->EvalMult(ciphertexts[i], pti);
        cc->EvalAddInPlace(weightedSum, tmp);
    }

    cc->ModReduceInPlace(weightedSum);

    return weightedSum;
}


Ciphertext<DCRTPoly> InnerEvalPolyPS(ConstCiphertext<DCRTPoly> x,
                                                         const std::vector<int64_t>& coefficients, uint32_t k,
                                                         uint32_t m, std::vector<Ciphertext<DCRTPoly>>& powers,
                                                         std::vector<Ciphertext<DCRTPoly>>& powers2, const size_t& numslots) {
    auto cc = x->GetCryptoContext();
    auto p = cc->GetCryptoParameters()->GetPlaintextModulus();

    // Compute k*2^m because we use it often
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Divide coefficients by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(int32_t(k2m2k + k) + 1, 0);
    xkm.back() = 1;

    auto divqr = LongDivisionPoly(coefficients, xkm, p);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        if(r2[int32_t(k2m2k)] > 0)
            r2[int32_t(k2m2k)] -= 1;
        else
            r2[int32_t(k2m2k)] += p - 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0);
        r2.back() = p - 1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPoly(r2, divqr->q, p);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0);
    s2.back() = 1;

    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                // Duhyeong: Cannot find ctxt-const mult API for BGV...
                std::vector<int64_t> vec(numslots, divcs->q[1]);
                Plaintext pt;
                pt = cc->MakePackedPlaintext(vec); 
                cu = cc->EvalMult(powers.front(), pt);
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = EvalLinearWSumMutable(ctxs, weights, numslots);
        }

        // adds the free term (at x^0)
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divcs->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        cc->EvalAddInPlace(cu, pt);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPS(x, divqr->q, k, m - 1, powers, powers2, numslots);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }

            qu = EvalLinearWSumMutable(ctxs, weights, numslots);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divqr->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        cc->EvalAddInPlace(qu, pt);
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su = qu->Clone();
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPS(x, s2, k, m - 1, powers, powers2, numslots);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }

                su = EvalLinearWSumMutable(ctxs, weights, numslots);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            // Duhyeong: Cannot find ctxt-const add API for BGV...
            std::vector<int64_t> vec(numslots, s2.front());
            Plaintext pt;
            pt = cc->MakePackedPlaintext(vec); 
            cc->EvalAddInPlace(su, pt);
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divcs->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        result = cc->EvalAdd(powers2[m - 1], pt);
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);

    return result;
}

Ciphertext<DCRTPoly> EvalPolyPS(ConstCiphertext<DCRTPoly> x, const std::vector<int64_t>& coefficients, const size_t& numslots){

    uint32_t n = Degree(coefficients);

    std::vector<int64_t> f2 = coefficients;

    // Make sure the coefficients do not have the dominant terms zero
    if (coefficients[coefficients.size() - 1] == 0)
        f2.resize(n + 1);

    std::vector<uint32_t> degs = ComputeDegreesPS(n);
    uint32_t k                 = degs[0];
    uint32_t m                 = degs[1];

    //  std::cerr << "\n Degree: n = " << n << ", k = " << k << ", m = " << m << endl;

    // TODO: (Andrey) Below all indices are set to 1?
    // set the indices for the powers of x that need to be computed to 1
    std::vector<int32_t> indices(k, 0);
    for (size_t i = k; i > 0; i--) {
        if (!(i & (i - 1))) {
            // if i is a power of 2
            indices[i - 1] = 1;
        }
        else {
            // non-power of 2
            indices[i - 1]   = 1;
            int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
            int64_t rem      = i % powerOf2;
            if (indices[rem - 1] == 0)
                indices[rem - 1] = 1;

            // while rem is not a power of 2
            // set indices required to compute rem to 1
            while ((rem & (rem - 1))) {
                powerOf2 = 1 << (int64_t)std::floor(std::log2(rem));
                rem      = rem % powerOf2;
                if (indices[rem - 1] == 0)
                    indices[rem - 1] = 1;
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers(k);
    powers[0] = x->Clone();
    auto cc   = x->GetCryptoContext();

    // computes all powers up to k for x
    for (size_t i = 2; i <= k; i++) {
        if (!(i & (i - 1))) {
            // if i is a power of two
            powers[i - 1] = cc->EvalSquare(powers[i / 2 - 1]);
            cc->ModReduceInPlace(powers[i - 1]);
        }
        else {
            if (indices[i - 1] == 1) {
                // non-power of 2
                int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
                int64_t rem      = i % powerOf2;
                usint levelDiff  = powers[powerOf2 - 1]->GetLevel() - powers[rem - 1]->GetLevel();
                cc->LevelReduceInPlace(powers[rem - 1], nullptr, levelDiff);
                powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
                cc->ModReduceInPlace(powers[i - 1]);
            }
        }
    }

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersBGVRNS>(powers[k - 1]->GetCryptoParameters());

    auto p = cryptoParams->GetPlaintextModulus();

    auto algo = cc->GetScheme();

    if (cryptoParams->GetScalingTechnique() == FIXEDMANUAL) {
        // brings all powers of x to the same level
        for (size_t i = 1; i < k; i++) {
            if (indices[i - 1] == 1) {
                usint levelDiff = powers[k - 1]->GetLevel() - powers[i - 1]->GetLevel();
                cc->LevelReduceInPlace(powers[i - 1], nullptr, levelDiff);
            }
        }
    }
    else {
        for (size_t i = 1; i < k; i++) {
            if (indices[i - 1] == 1) {
                algo->AdjustLevelsAndDepthInPlace(powers[i - 1], powers[k - 1]);
            }
        }
    }

    std::vector<Ciphertext<DCRTPoly>> powers2(m);

    // computes powers of form k*2^i for x
    powers2.front() = powers.back()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        powers2[i] = cc->EvalSquare(powers2[i - 1]);
        cc->ModReduceInPlace(powers2[i]);
    }

    // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
    auto power2km1 = powers2.front()->Clone();
    for (uint32_t i = 1; i < m; i++) {
        power2km1 = cc->EvalMult(power2km1, powers2[i]);
        cc->ModReduceInPlace(power2km1);
    }

    // Compute k*2^{m-1}-k because we use it a lot
    uint32_t k2m2k = k * (1 << (m - 1)) - k;

    // Add x^{k(2^m - 1)} to the polynomial that has to be evaluated
    // std::vector<int64_t> f2 = coefficients;
    f2.resize(2 * k2m2k + k + 1, 0);
    f2.back() = 1;

    // Divide f2 by x^{k*2^{m-1}}
    std::vector<int64_t> xkm(int32_t(k2m2k + k) + 1, 0);
    xkm.back() = 1;
    auto divqr = LongDivisionPoly(f2, xkm, p);

    // Subtract x^{k(2^{m-1} - 1)} from r
    std::vector<int64_t> r2 = divqr->r;
    if (int32_t(k2m2k - Degree(divqr->r)) <= 0) {
        if(r2[int32_t(k2m2k)] > 0)
            r2[int32_t(k2m2k)] -= 1;
        else
            r2[int32_t(k2m2k)] += p - 1;
        r2.resize(Degree(r2) + 1);
    }
    else {
        r2.resize(int32_t(k2m2k + 1), 0);
        r2.back() = p - 1;
    }

    // Divide r2 by q
    auto divcs = LongDivisionPoly(r2, divqr->q, p);

    // Add x^{k(2^{m-1} - 1)} to s
    std::vector<int64_t> s2 = divcs->r;
    s2.resize(int32_t(k2m2k + 1), 0);
    s2.back() = 1;

    // Evaluate c at u
    Ciphertext<DCRTPoly> cu;
    uint32_t dc = Degree(divcs->q);
    bool flag_c = false;

    if (dc >= 1) {
        if (dc == 1) {
            if (divcs->q[1] != 1) {
                // Duhyeong: Cannot find ctxt-const mult API for BGV...
                std::vector<int64_t> vec(numslots, divcs->q[1]);
                Plaintext pt;
                pt = cc->MakePackedPlaintext(vec); 
                cu = cc->EvalMult(powers.front(), pt);
                // Do rescaling after scalar multiplication
                cc->ModReduceInPlace(cu);
            }
            else {
                cu = powers.front()->Clone();
            }
        }
        else {
            std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
            std::vector<int64_t> weights(dc);

            for (uint32_t i = 0; i < dc; i++) {
                ctxs[i]    = powers[i];
                weights[i] = divcs->q[i + 1];
            }

            cu = EvalLinearWSumMutable(ctxs, weights, numslots);
        }

        // adds the free term (at x^0)
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divcs->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        cc->EvalAddInPlace(cu, pt);
        flag_c = true;
    }

    // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
    Ciphertext<DCRTPoly> qu;

    if (Degree(divqr->q) > k) {
        qu = InnerEvalPolyPS(x, divqr->q, k, m - 1, powers, powers2, numslots);
    }
    else {
        // dq = k from construction
        // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
        auto qcopy = divqr->q;
        qcopy.resize(k);
        if (Degree(qcopy) > 0) {
            std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
            std::vector<int64_t> weights(Degree(qcopy));

            for (uint32_t i = 0; i < Degree(qcopy); i++) {
                ctxs[i]    = powers[i];
                weights[i] = divqr->q[i + 1];
            }
            qu = EvalLinearWSumMutable(ctxs, weights, numslots);
            // the highest order term will always be 1 because q is monic
            cc->EvalAddInPlace(qu, powers[k - 1]);
        }
        else {
            qu = powers[k - 1]->Clone();
        }
        // adds the free term (at x^0)
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divqr->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        cc->EvalAddInPlace(qu, pt);
    }

    uint32_t ds = Degree(s2);
    Ciphertext<DCRTPoly> su;

    if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
        su = qu->Clone();
    }
    else {
        if (ds > k) {
            su = InnerEvalPolyPS(x, s2, k, m - 1, powers, powers2, numslots);
        }
        else {
            // ds = k from construction
            // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
            auto scopy = s2;
            scopy.resize(k);
            if (Degree(scopy) > 0) {
                std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
                std::vector<int64_t> weights(Degree(scopy));

                for (uint32_t i = 0; i < Degree(scopy); i++) {
                    ctxs[i]    = powers[i];
                    weights[i] = s2[i + 1];
                }
                su = EvalLinearWSumMutable(ctxs, weights, numslots);
                // the highest order term will always be 1 because q is monic
                cc->EvalAddInPlace(su, powers[k - 1]);
            }
            else {
                su = powers[k - 1]->Clone();
            }
            // adds the free term (at x^0)
            // Duhyeong: Cannot find ctxt-const add API for BGV...
            std::vector<int64_t> vec(numslots, s2.front());
            Plaintext pt;
            pt = cc->MakePackedPlaintext(vec); 
            cc->EvalAddInPlace(su, pt);
        }
    }

    Ciphertext<DCRTPoly> result;

    if (flag_c) {
        result = cc->EvalAdd(powers2[m - 1], cu);
    }
    else {
        // Duhyeong: Cannot find ctxt-const add API for BGV...
        std::vector<int64_t> vec(numslots, divcs->q.front());
        Plaintext pt;
        pt = cc->MakePackedPlaintext(vec); 
        result = cc->EvalAdd(powers2[m - 1], pt);
    }

    result = cc->EvalMult(result, qu);
    cc->ModReduceInPlace(result);
    cc->EvalAddInPlace(result, su);
    cc->EvalSubInPlace(result, power2km1);

    return result;
}


// int64_t powerMod(int64_t& a, int64_t& power, int64_t& p) {
//     int64_t result = 1;
//     int64_t tmp = power;
//     int64_t a_power = a;
//     while(tmp > 0)
//     {
//         if (tmp & 1)
//             result = (result * a_power) % p;
//         a_power = (a_power * a_power) % p;
//         tmp >>= 1;
//     }

//     return result;
// }

// Duhyeong: Refer to eprint 2021/315 (Eq. 5 in Section 3.2)
// "Less-than" function
Ciphertext<DCRTPoly> EvalComp(ConstCiphertext<DCRTPoly> x, ConstCiphertext<DCRTPoly> y, const size_t& numslots) {
    // Compute the coefficients of the polynomial corresponding to the sign function modulo p   
    auto cc = x->GetCryptoContext();
    auto p = cc->GetCryptoParameters()->GetPlaintextModulus();
    uint64_t p_half = (p - 1) / 2;
    std::vector<int64_t> coefficients(p, 0);
    std::vector<int64_t> powList(p_half, 1);
    std::vector<int64_t> sqList(p_half, 1);
    coefficients[p - 1] = (p + 1) / 2;

    for(uint64_t a = 0; a < p_half; a++){
        sqList[a] = ((a+1)*(a+1)) % p;
    }
    for (uint64_t i = p - 2; i > 0; i--){
        if(i == p - 2){
            for(uint64_t a = 0; a < p_half; a++){
                powList[a] = a + 1;
            }
            for(uint64_t a = 0; a < p_half; a++){
                coefficients[i] = (coefficients[i] + powList[a]) % p;
            }
        }
        else if(i % 2 != 0){
            for(uint64_t a = 0; a < p_half; a++){
                powList[a] = (powList[a] * sqList[a]) % p;
            }
            for(uint64_t a = 0; a < p_half; a++){
                coefficients[i] = (coefficients[i] + powList[a]) % p;
            }
        }
    }
    std::cout << "Comparison Coefficient Gen done  ... ";

    auto diff = cc->EvalSub(x, y);

    Ciphertext<DCRTPoly> result;

    result = EvalPolyPS(diff, coefficients, numslots);

    return result;
}