import pyteal as pt
import beaker as bkr

# Transcribed from https://research.metastate.dev/plonk-by-hand-part-3-verification/ 
# for Kate commitments

# 1) Validate all ec points are on the curve (a,b,c,z,...)
# 2) Validate circuit field elements are in the field ( just < field characteristic?)
# 3) Validate public inputs to circuit are in the field
# 4) Evaluate the zero polynomial Zh at z (z^n-1)
# 5) compute lagrange poly L[1](z): (z^n-1)/(n(z-1)) - step5 == 0
# 6) compute public input polynomial: sum([W[i]*L[i](z) for i in range(len(W))])
# 7) compute quotient polynomial eval: ...
# 8) compute first part of batched polynomial commitment: ...
# 9) compute full batched polynomial commitment: ...
# 10) compute group encoded batch eval [E]: ...
# 11) Batch validate all equations: ...




class VerificationKey(pt.abi.NamedTuple):
    pass
    # struct VerificationKey {
    #     uint256 domain_size;
    #     uint256 num_inputs;
    #     PairingsBn254.Fr omega;
    #     // STATE_WIDTH for witness + multiplication + constant
    #     PairingsBn254.G1Point[STATE_WIDTH+2] selector_commitments; 
    #     PairingsBn254.G1Point[1] next_step_selector_commitments;
    #     PairingsBn254.G1Point[STATE_WIDTH] permutation_commitments;
    #     PairingsBn254.Fr[STATE_WIDTH-1] permutation_non_residues;
    #     PairingsBn254.G2Point g2_x;
    # }
    
class Proof(pt.abi.NamedTuple):
    pass
    #struct Proof {
    #    uint256[] input_values;
    #    PairingsBn254.G1Point[STATE_WIDTH] wire_commitments;
    #    PairingsBn254.G1Point grand_product_commitment;
    #    PairingsBn254.G1Point[STATE_WIDTH] quotient_poly_commitments;
    #    PairingsBn254.Fr[STATE_WIDTH] wire_values_at_z;
    #    PairingsBn254.Fr[1] wire_values_at_z_omega;
    #    PairingsBn254.Fr grand_product_at_z_omega;
    #    PairingsBn254.Fr quotient_polynomial_at_z;
    #    PairingsBn254.Fr linearization_polynomial_at_z;
    #    PairingsBn254.Fr[STATE_WIDTH-1] permutation_polynomials_at_z;
    
    #    PairingsBn254.G1Point opening_at_z_proof;
    #    PairingsBn254.G1Point opening_at_z_omega_proof;
    #}
    
class PartialVerifierState(pt.abi.NamedTuple):
    pass
    #struct PartialVerifierState {
    #    PairingsBn254.Fr alpha;
    #    PairingsBn254.Fr beta;
    #    PairingsBn254.Fr gamma;
    #    PairingsBn254.Fr v;
    #    PairingsBn254.Fr u;
    #    PairingsBn254.Fr z;
    #    PairingsBn254.Fr[] cached_lagrange_evals;
    #}
    

class PlonkVerifier(bkr.Application):

    pass
