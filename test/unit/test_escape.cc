#include<gtest/gtest.h>
#include<iostream>
#include<cstring>

extern "C" {
    struct NODE;
    NODE* make_str_node(const char *, size_t, int);
    const char* get_node_str(const NODE *);
    NODE* create_symtab();
}

TEST(EscapeTest, makeStrNode)
{
    NODE *str_node = make_str_node("he\\ahe", std::strlen("he\\ahe"), 1 /*Scan for escape*/);
    std::cout<<get_node_str(str_node)<<std::endl;
}

TEST(SymTabCreate, createSymTab)
{
    (void)create_symtab();
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
